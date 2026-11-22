// ============================================================
// PIPELINE CI/CD DEVSECOPS - Juice Shop
// Correspondance avec le plan du professeur :
//  2.1 Declenchement          : pollSCM (GitHub verifie toutes les 5 min)
//  2.2 / 2.5 Construction     : etape "Construction de l image"
//  2.3 Tests                  : etape "Tests fonctionnels"
//  3.1 Semgrep (SAST)         : etape "SAST - Semgrep"
//  3.2 Dependency-Check (SCA) : etape "SCA - Dependency-Check"
//  3.3 Trivy (image)          : etape "Analyse de l image - Trivy"
//  3.4 OWASP ZAP (DAST)       : etape "DAST - OWASP ZAP"
//  3.5 Seuils                 : politique ci-dessous + deux Quality Gates
//  2.6 Deploiement            : etape "Deploiement Kubernetes"
//  4.3.5 Remontee resultats   : dossier reports archive + synthese.txt
// ============================================================

// ===== POLITIQUE DE SECURITE =====
// Semgrep          : echec si une regle de gravite ERROR se declenche
// Dependency-Check : echec si une faille a un score CVSS >= 9
// Trivy            : echec si une faille CRITICAL avec correctif disponible
// ZAP              : echec si au moins une alerte Moyenne ou Haute
// Panne d'un outil : toujours un echec (rouge)

def enregistrer(String outil, int rc, String rapport) {
    if (!fileExists(rapport)) {
        error("${outil} : rapport ${rapport} absent. L'outil est en panne, ce n'est pas une faille detectee.")
    }
    if (rc != 0) {
        env.VIOLATIONS = (env.VIOLATIONS ?: '') + outil + ' '
        echo "SEUIL DEPASSE : ${outil} (code ${rc})"
    } else {
        echo "${outil} : seuil respecte"
    }
}

def decider(String mode, String etape) {
    def v = env.VIOLATIONS ?: ''
    if (v == '') {
        echo "QUALITY GATE (${etape}) : OK, aucun seuil depasse"
    } else if (mode == 'STRICT') {
        error("QUALITY GATE (${etape}) : BLOQUE en mode STRICT. Seuils depasses : ${v}")
    } else {
        unstable("QUALITY GATE (${etape}) : seuils depasses (${v}) mais mode AUDIT, le pipeline continue")
    }
}

pipeline {
    agent any
    options {
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 3, unit: 'HOURS')
    }
    triggers {
        pollSCM('H/5 * * * *')
    }
    parameters {
        choice(name: 'MODE', choices: ['AUDIT', 'STRICT'], description: 'AUDIT = on continue et le build devient orange. STRICT = on bloque si un seuil est depasse.')
        choice(name: 'SOURCE_IMAGE', choices: ['SOURCES', 'OFFICIELLE'], description: 'SOURCES = construire l image avec le Dockerfile du depot (repli automatique sur l image officielle si ca echoue). OFFICIELLE = telecharger l image officielle.')
    }
    environment {
        IMAGE = "juice-shop:build-${BUILD_NUMBER}"
    }
    stages {
        stage('Preparation') {
            steps {
                script {
                    env.MODE_EFFECTIF = params.MODE ?: 'AUDIT'
                    env.SOURCE_EFFECTIVE = params.SOURCE_IMAGE ?: 'SOURCES'
                    env.VIOLATIONS = ''
                    env.ORIGINE_IMAGE = 'inconnue'
                }
                echo "Mode : ${env.MODE_EFFECTIF} | Source image : ${env.SOURCE_EFFECTIVE} | Image : ${env.IMAGE}"
                sh 'rm -rf reports && mkdir -p reports && chmod 777 reports'
                sh '''
                    docker images --format "{{.Repository}}:{{.Tag}}" | grep "^juice-shop:build-" | grep -v ":build-${BUILD_NUMBER}$" | xargs -r docker rmi || true
                    minikube image ls 2>/dev/null | grep "juice-shop:build-" | grep -v "build-${BUILD_NUMBER}$" | xargs -r -n1 minikube image rm || true
                '''
            }
        }
        stage('Construction de l image (plan 2.2 / 2.5)') {
            steps {
                script {
                    if (env.SOURCE_EFFECTIVE == 'SOURCES') {
                        def rc = sh(returnStatus: true, script: 'docker build -t "$IMAGE" .')
                        if (rc == 0) {
                            env.ORIGINE_IMAGE = 'sources du depot'
                        } else {
                            env.ORIGINE_IMAGE = 'officielle (repli apres echec du build)'
                            unstable('Construction depuis les sources impossible : image officielle utilisee a la place')
                        }
                    } else {
                        env.ORIGINE_IMAGE = 'officielle'
                    }
                    if (env.ORIGINE_IMAGE != 'sources du depot') {
                        sh '''
                            docker pull bkimminich/juice-shop:latest
                            docker tag bkimminich/juice-shop:latest "$IMAGE"
                        '''
                    }
                    sh 'docker inspect --format="{{.Id}}" "$IMAGE" > reports/image-id.txt'
                    sh 'docker images "$IMAGE"'
                    echo "Origine de l image : ${env.ORIGINE_IMAGE}"
                }
            }
        }
        stage('SAST - Semgrep (plan 3.1)') {
            steps {
                script {
                    def rc = sh(returnStatus: true, script: 'docker run --rm -v "$PWD":/src semgrep/semgrep semgrep scan --config=auto --severity ERROR --error --exclude=reports --json-output=reports/semgrep.json')
                    if (rc > 1) {
                        error("Semgrep en panne (code ${rc})")
                    }
                    enregistrer('Semgrep', rc, 'reports/semgrep.json')
                }
            }
        }
        stage('SCA - Dependency-Check (plan 3.2)') {
            steps {
                withCredentials([string(credentialsId: 'nvd-api-key', variable: 'NVD_KEY')]) {
                    script {
                        def rc = sh(returnStatus: true, script: '''
                            docker run --rm -v "$PWD":/src -v "$PWD/reports":/report -v dc-data:/usr/share/dependency-check/data owasp/dependency-check:latest --scan /src --format HTML --format JSON --out /report --nvdApiKey "$NVD_KEY" --failOnCVSS 9 --exclude "**/reports/**" --exclude "**/.git/**" --disableNodeAudit --disableYarnAudit
                        ''')
                        enregistrer('Dependency-Check', rc, 'reports/dependency-check-report.json')
                    }
                }
            }
        }
        stage('Analyse de l image - Trivy (plan 3.3)') {
            steps {
                script {
                    sh 'docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/reports":/reports -v trivy-cache:/root/.cache/ aquasec/trivy:latest image --no-progress --format json --output /reports/trivy.json "$IMAGE"'
                    def rc = sh(returnStatus: true, script: 'docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache/ aquasec/trivy:latest image --no-progress --severity CRITICAL --ignore-unfixed --exit-code 1 "$IMAGE"')
                    enregistrer('Trivy', rc, 'reports/trivy.json')
                }
            }
        }
        stage('Quality Gate 1 - avant deploiement (plan 3.5)') {
            steps {
                script {
                    decider(env.MODE_EFFECTIF, 'avant deploiement')
                }
            }
        }
        stage('Deploiement Kubernetes (plan 2.6)') {
            steps {
                sh '''
                    minikube image load "$IMAGE"
                    minikube image ls | grep "juice-shop:build-${BUILD_NUMBER}" || { echo "Image absente de Minikube"; exit 1; }
                    kubectl delete deployment juice-shop-k8s --ignore-not-found=true
                    kubectl create deployment juice-shop-k8s --image="$IMAGE"
                    kubectl expose deployment juice-shop-k8s --type=NodePort --port=3000 || true
                '''
                script {
                    def rc = sh(returnStatus: true, script: 'kubectl rollout status deployment/juice-shop-k8s --timeout=300s')
                    if (rc != 0) {
                        sh 'kubectl get pods -o wide || true'
                        sh 'kubectl describe pod -l app=juice-shop-k8s | tail -40 || true'
                        sh 'kubectl logs -l app=juice-shop-k8s --tail=40 || true'
                        error('Le deploiement Kubernetes ne devient pas pret (voir le diagnostic ci-dessus).')
                    }
                }
                sh 'kubectl get pods'
            }
        }
        stage('Tests fonctionnels (plan 2.3)') {
            steps {
                sh '''
                    NODEPORT=$(kubectl get svc juice-shop-k8s -o jsonpath='{.spec.ports[0].nodePort}')
                    MINIKUBE_IP=$(minikube ip)
                    URL=http://$MINIKUBE_IP:$NODEPORT
                    CODE=000
                    for i in $(seq 1 24); do
                        CODE=$(curl -s -o /dev/null -m 5 -w "%{http_code}" "$URL/" || true)
                        echo "Essai $i : code HTTP recu = $CODE"
                        if [ "$CODE" = "200" ]; then
                            break
                        fi
                        sleep 5
                    done
                    CODE2=$(curl -s -o reports/search-response.json -m 10 -w "%{http_code}" "$URL/rest/products/search?q=apple" || true)
                    CODE3=$(curl -s -o /dev/null -m 10 -w "%{http_code}" "$URL/metrics" || true)
                    echo "accueil=$CODE recherche=$CODE2 metrics_informatif=$CODE3" | tee reports/tests-fonctionnels.txt
                    test "$CODE" = "200"
                    test "$CODE2" = "200"
                    grep -q '"status":"success"' reports/search-response.json
                '''
            }
        }
        stage('DAST - OWASP ZAP (plan 3.4)') {
            steps {
                script {
                    def rc = sh(returnStatus: true, script: '''
                        NODEPORT=$(kubectl get svc juice-shop-k8s -o jsonpath='{.spec.ports[0].nodePort}')
                        MINIKUBE_IP=$(minikube ip)
                        docker run --rm --network minikube -v "$PWD/reports":/zap/wrk:rw zaproxy/zap-stable zap-baseline.py -t http://$MINIKUBE_IP:$NODEPORT -r zap-report.html -J zap-report.json
                    ''')
                    echo "Code de retour ZAP = ${rc} (0 OK, 1 FAIL, 2 WARN, 3 erreur de l'outil)"
                    if (rc == 3 || !fileExists('reports/zap-report.json')) {
                        error('ZAP en panne : rapport absent ou erreur de l outil.')
                    }
                    def moyen = sh(script: "grep -Eo '\"riskcode\" *: *\"?[23]\"?' reports/zap-report.json | wc -l", returnStdout: true).trim().toInteger()
                    echo "Alertes ZAP de gravite Moyenne ou Haute : ${moyen}"
                    enregistrer('ZAP', moyen > 0 ? 1 : 0, 'reports/zap-report.json')
                }
            }
        }
        stage('Quality Gate 2 - apres test dynamique (plan 3.5)') {
            steps {
                script {
                    decider(env.MODE_EFFECTIF, 'apres test dynamique')
                }
            }
        }
    }
    post {
        always {
            sh 'mkdir -p reports'
            writeFile file: 'reports/synthese.txt', text: "mode=${env.MODE_EFFECTIF}\nimage=${env.IMAGE}\norigine_image=${env.ORIGINE_IMAGE}\nbuild=${env.BUILD_NUMBER}\nseuils_depasses=${env.VIOLATIONS ?: 'aucun'}\n"
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
    }
}
