// =====================================================================
// Pipeline DevSecOps - OWASP Juice Shop (PFA)
// Plan : Chapitre 3 section 2 (architecture du pipeline) et section 3
// (positionnement des outils + seuils), Chapitre 4 sections 2 et 3.
//
// Philosophie :
//   - Les scanners ne cassent JAMAIS le build : ils produisent des rapports.
//   - Une seule etape DECIDE : le Security Gate (ci/security_gate.py).
//   - Il bloque les NOUVELLES failles HIGH/CRITICAL (baseline + cliquet).
//   - Pas de rapport complet = pas de deploiement.
//
// Hypotheses (a verifier sur ta machine) :
//   - Pipeline lance en "Pipeline script from SCM" (checkout scm).
//   - L'agent Jenkins est Linux (ou WSL) et l'utilisateur jenkins peut
//     utiliser docker, semgrep, trivy, python3 (+ dependency-check,
//     kubectl, minikube si ces options sont activees).
//   - Le fichier ci/security_gate.py est dans le depot a cote du Jenkinsfile.
// =====================================================================
pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '15'))
        disableConcurrentBuilds()
    }

    parameters {
        booleanParam(name: 'RESET_BASELINE', defaultValue: false,
            description: 'Recree la baseline a partir de ce build (a cocher apres un gros nettoyage). Pas de deploiement.')
        booleanParam(name: 'FAIL_ON_CRITICAL', defaultValue: false,
            description: 'Jalon 1 : bloque aussi toute faille CRITICAL deja existante.')
        booleanParam(name: 'RUN_DEPCHECK', defaultValue: true,
            description: 'OWASP Dependency-Check (lent au premier lancement : base NVD a telecharger).')
        booleanParam(name: 'DEPLOY', defaultValue: true,
            description: 'Deployer sur Kubernetes (Minikube) si le Security Gate est valide.')
    }

    environment {
        IMAGE         = "pfa/juice-shop:${env.BUILD_NUMBER}"
        REPORTS       = "${env.WORKSPACE}/security-reports"
        NET           = "pfa-net-${env.BUILD_NUMBER}"
        // Baseline conservee dans le volume Jenkins : elle survit entre les builds.
        BASELINE_FILE = "${env.JENKINS_HOME}/security-baseline/baseline.json"
        K8S_NAMESPACE = 'juice-shop'
    }

    stages {

        // ---------------------------------------------------------------
        // Ch.3 2.1 - Declenchement : recuperation du code
        // ---------------------------------------------------------------
        stage('1. Checkout') {
            steps {
                checkout scm
                sh 'rm -rf "$REPORTS" && mkdir -p "$REPORTS"'
            }
        }

        // ---------------------------------------------------------------
        // Verification des outils : echoue VITE avec un message clair
        // au lieu d'un echec obscur au milieu du pipeline.
        // ---------------------------------------------------------------
        stage('2. Preflight (outils)') {
            steps {
                script {
                    def tools = ['docker', 'python3', 'semgrep', 'trivy']
                    if (params.DEPLOY)       { tools += ['kubectl', 'minikube'] }
                    withEnv(["TOOLS=${tools.join(' ')}"]) {
                        sh '''
                            missing=""
                            for t in $TOOLS; do
                                command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
                            done
                            if [ -n "$missing" ]; then
                                echo "OUTILS MANQUANTS ou hors PATH pour l'utilisateur Jenkins :$missing"
                                exit 1
                            fi
                            test -f ci/security_gate.py || { echo "ci/security_gate.py introuvable dans le depot"; exit 1; }
                            docker version --format 'Docker serveur : {{.Server.Version}}'
                            semgrep --version
                            trivy --version | head -1
                            python3 --version
                        '''
                    }
                }
            }
        }

        // ---------------------------------------------------------------
        // Ch.3 2.2 / Ch.4 2.2 - Build de l'application (image Docker)
        // Echec ici = vraie erreur de build : FAILURE legitime.
        // ---------------------------------------------------------------
        stage('3. Build image Docker') {
            steps {
                // L'application cible est recuperee en image officielle
                // (evite la recompilation npm, sensible au reseau)
                sh '''
                    docker pull bkimminich/juice-shop:latest
                    docker tag bkimminich/juice-shop:latest "$IMAGE"
                '''
            }
        }

        // ---------------------------------------------------------------
        // Ch.3 2.4 / 3.1-3.3 - Scans SAST, SCA et image, en parallele.
        // Aucun de ces outils ne fait echouer le build sur une faille :
        // ils ecrivent un rapport JSON. Si l'outil lui-meme plante,
        // le build passe UNSTABLE (donc pas de deploiement).
        // ---------------------------------------------------------------
        stage('4. Scans de securite') {
            parallel {

                stage('Semgrep (SAST)') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                semgrep scan \
                                    --config p/owasp-top-ten --config p/javascript \
                                    --config p/typescript --config p/secrets \
                                    --exclude node_modules --exclude frontend/dist \
                                    --metrics=off --quiet \
                                    --json --output "$REPORTS/semgrep.json" .
                            '''
                        }
                    }
                }

                stage('Dependency-Check (SCA)') {
                    when { expression { params.RUN_DEPCHECK } }
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            script {
                                // Cle API NVD : Jenkins > Identifiants > "Secret text" avec l'ID nvd-api-key.
                                // Sans cle, le telechargement de la base est tres lent et souvent limite.
                                def hasKey = true
                                try {
                                    withCredentials([string(credentialsId: 'nvd-api-key', variable: 'NVD_KEY')]) {
                                        echo 'Cle NVD trouvee.'
                                    }
                                } catch (ignored) {
                                    hasKey = false
                                    echo 'ATTENTION : identifiant nvd-api-key absent, Dependency-Check sera lent ou limite.'
                                }
                                // Dependency-Check tourne dans Docker (image owasp/dependency-check)
                                // avec le volume dc-data qui conserve la base NVD deja telechargee.
                                def dc = '''
                                    mkdir -p "$REPORTS/dc"
                                    chmod 777 "$REPORTS/dc"
                                    # Code 14 = des archives pieges de Juice Shop n'ont pas pu etre lues
                                    # (zip chiffre, zip-slip). Le rapport est quand meme ecrit :
                                    # on tolere ce code et on verifie que le rapport existe.
                                    docker run --rm \
                                        -v "$WORKSPACE:/src:ro" \
                                        -v dc-data:/usr/share/dependency-check/data \
                                        -v "$REPORTS/dc:/report:rw" \
                                        owasp/dependency-check:latest \
                                        --project JuiceShop --scan /src \
                                        --exclude "**/node_modules/**" --exclude "**/dist/**" \
                                        --disableNodeAudit \
                                        --format JSON --out /report $NVD_ARG || echo "dependency-check a termine avec un code non nul (voir ci-dessus)"
                                    test -s "$REPORTS/dc/dependency-check-report.json"
                                    cp "$REPORTS/dc/dependency-check-report.json" "$REPORTS/dependency-check.json"
                                '''
                                if (hasKey) {
                                    withCredentials([string(credentialsId: 'nvd-api-key', variable: 'NVD_KEY')]) {
                                        sh 'export NVD_ARG="--nvdApiKey $NVD_KEY"\n' + dc
                                    }
                                } else {
                                    sh 'export NVD_ARG=""\n' + dc
                                }
                            }
                        }
                    }
                }

                stage('Trivy (image)') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                trivy image --scanners vuln \
                                    --severity MEDIUM,HIGH,CRITICAL \
                                    --timeout 20m --quiet \
                                    --format json --output "$REPORTS/trivy.json" "$IMAGE"
                            '''
                        }
                    }
                }
            }
        }

        // ---------------------------------------------------------------
        // Ch.3 2.6 / 3.4 - Staging ISOLE (reseau Docker dedie) + test
        // fonctionnel de demarrage + scan dynamique OWASP ZAP.
        // ---------------------------------------------------------------
        stage('5. Staging, test fonctionnel et DAST (ZAP)') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        docker network create "$NET"
                        docker run -d --name "juice-staging-$BUILD_NUMBER" \
                            --network "$NET" --network-alias juice "$IMAGE"

                        # Test fonctionnel : l'application doit repondre (30 essais x 5 s)
                        ok=0
                        for i in $(seq 1 30); do
                            if docker run --rm --network "$NET" curlimages/curl:8.10.1 \
                                   -fsS http://juice:3000/rest/admin/application-version | grep -q version; then
                                ok=1; echo "Application prete (essai $i)"; break
                            fi
                            echo "attente de l'application ($i/30)..."; sleep 5
                        done
                        if [ "$ok" -ne 1 ]; then
                            echo "L'application n'a pas demarre. Derniers logs :"
                            docker logs "juice-staging-$BUILD_NUMBER" 2>&1 | tail -50
                            exit 1
                        fi

                        # Scan dynamique ZAP (baseline). Le code de retour de ZAP depend
                        # des alertes trouvees : c'est le gate qui decide, donc "|| true".
                        mkdir -p "$REPORTS/zap-wrk"
                        chmod 777 "$REPORTS/zap-wrk"
                        docker run --rm --name "zap-$BUILD_NUMBER" --network "$NET" \
                            -v "$REPORTS/zap-wrk:/zap/wrk:rw" \
                            ghcr.io/zaproxy/zaproxy:stable \
                            zap-baseline.py -t http://juice:3000 -J zap.json -m 3 -I || true
                        cp "$REPORTS/zap-wrk/zap.json" "$REPORTS/zap.json"
                        test -s "$REPORTS/zap.json"
                    '''
                }
            }
        }

        // ---------------------------------------------------------------
        // Ch.5 3.1 - Point d'accroche du module IA (conditionnel).
        // Le fichier security-reports/findings.json (alertes normalisees)
        // est son jeu de donnees d'entree. Etape informative pour l'instant.
        // ---------------------------------------------------------------
        stage('6. Module IA (Chapitre 5)') {
            when { expression { fileExists('ai_module/analyze.py') } }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh 'python3 ai_module/analyze.py --findings "$REPORTS/findings.json" --out "$REPORTS/ai_analysis.json"'
                }
            }
        }

        // ---------------------------------------------------------------
        // Ch.3 3.5 - SECURITY GATE : l'unique juge du pipeline.
        // Code 0 = valide | 1 = nouvelles failles graves | 2 = rapports incomplets
        // ---------------------------------------------------------------
        stage('7. Security Gate') {
            steps {
                script {
                    def required = ['semgrep', 'trivy', 'zap']
                    if (params.RUN_DEPCHECK) { required << 'dependency-check' }
                    def args = "--reports '${env.REPORTS}' --baseline '${env.BASELINE_FILE}' --require ${required.join(',')}"
                    if (params.RESET_BASELINE)  { args += ' --reset-baseline' }
                    if (params.FAIL_ON_CRITICAL) { args += ' --fail-on-critical' }

                    def rc = sh(script: "python3 ci/security_gate.py ${args}", returnStatus: true)
                    if (rc == 1) {
                        error('SECURITY GATE : nouvelles failles HIGH/CRITICAL detectees. Voir le tableau ci-dessus.')
                    } else if (rc != 0) {
                        unstable('SECURITY GATE : rapports incomplets ou erreur du script. Aucun deploiement.')
                    }
                }
            }
        }

        // ---------------------------------------------------------------
        // Ch.3 2.6 / Ch.4 2.5 - Deploiement sur Kubernetes (Minikube),
        // uniquement si TOUT est au vert (gate valide, aucun outil plante).
        // Conteneur durci : non-root, aucune capacite Linux, pas d'escalade.
        // ---------------------------------------------------------------
        stage('8. Deploiement Kubernetes') {
            when {
                allOf {
                    expression { params.DEPLOY }
                    expression { !params.RESET_BASELINE }
                    expression { currentBuild.currentResult == 'SUCCESS' }
                }
            }
            steps {
                sh 'minikube image load "$IMAGE"'
                writeFile file: 'k8s-generated.yaml', text: """\
apiVersion: v1
kind: Namespace
metadata:
  name: ${env.K8S_NAMESPACE}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: juice-shop
  namespace: ${env.K8S_NAMESPACE}
  labels:
    app: juice-shop
spec:
  replicas: 1
  selector:
    matchLabels:
      app: juice-shop
  template:
    metadata:
      labels:
        app: juice-shop
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: juice-shop
          image: ${env.IMAGE}
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 3000
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          readinessProbe:
            httpGet:
              path: /rest/admin/application-version
              port: 3000
            initialDelaySeconds: 10
            periodSeconds: 5
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
---
apiVersion: v1
kind: Service
metadata:
  name: juice-shop
  namespace: ${env.K8S_NAMESPACE}
spec:
  type: NodePort
  selector:
    app: juice-shop
  ports:
    - port: 3000
      targetPort: 3000
      nodePort: 30080
"""
                sh 'kubectl apply -f k8s-generated.yaml'
                sh 'kubectl -n "$K8S_NAMESPACE" rollout status deployment/juice-shop --timeout=180s'
            }
        }
    }

    post {
        always {
            // Nettoyage systematique : conteneurs et reseau de ce build uniquement.
            sh '''
                docker rm -f "juice-staging-$BUILD_NUMBER" "zap-$BUILD_NUMBER" >/dev/null 2>&1 || true
                docker network rm "$NET" >/dev/null 2>&1 || true
            '''
            // Preuves pour le Chapitre 6 : rapports bruts, findings.json, summary.json.
            archiveArtifacts artifacts: 'security-reports/*.json', allowEmptyArchive: true
        }
        success { echo 'Pipeline termine : build SUCCESS.' }
        unstable { echo 'Build UNSTABLE : un outil a plante ou un rapport manque. Pas de deploiement.' }
        failure  { echo 'Build FAILURE : regarde le premier stage rouge, pas le dernier.' }
    }
}
