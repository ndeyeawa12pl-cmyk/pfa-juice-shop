
// =====================================================================
// Pipeline DevSecOps - OWASP Juice Shop (PFA)
// Déploiement local : Minikube
//
// Politique : les vulnérabilités connues sont suivies dans une baseline.
// Seules les nouvelles vulnérabilités CRITICAL (ou les escalades vers
// CRITICAL) bloquent. Les erreurs techniques et rapports incomplets bloquent
// également : un contrôle non exécuté ne peut pas être déclaré réussi.
// =====================================================================

pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 90, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        disableConcurrentBuilds()
    }

    parameters {
        string(
            name: 'APP_CONTEXT',
            defaultValue: '.',
            description: 'Dossier contenant le Dockerfile de Juice Shop (par défaut : racine du dépôt).'
        )
        booleanParam(
            name: 'RUN_DEPCHECK',
            defaultValue: true,
            description: 'Exécuter OWASP Dependency-Check (peut être long au premier lancement).'
        )
        booleanParam(
            name: 'RESET_BASELINE',
            defaultValue: false,
            description: 'Créer/remplacer la baseline avec les résultats de ce build. À utiliser uniquement après revue des rapports.'
        )
        booleanParam(
            name: 'DEPLOY',
            defaultValue: true,
            description: 'Déployer sur le cluster Minikube local après validation de tous les contrôles.'
        )
    }

    environment {
        IMAGE         = "pfa/juice-shop:${env.BUILD_NUMBER}"
        REPORTS       = "${env.WORKSPACE}/security-reports"
        NET           = "pfa-juice-net-${env.BUILD_NUMBER}"
        BASELINE_FILE = "${env.JENKINS_HOME}/security-baseline/${env.JOB_NAME}/baseline.json"
        K8S_NAMESPACE = 'juice-shop'
        GATE_RC       = '99'
    }

    stages {
        stage('1. Checkout') {
            steps {
                checkout scm
                sh '''
                    set -eu
                    rm -rf "$REPORTS"
                    mkdir -p "$REPORTS"
                    mkdir -p "$(dirname "$BASELINE_FILE")"
                    test -f ci/security_gate.py || {
                        echo "ERREUR : ci/security_gate.py est introuvable dans le dépôt."
                        exit 1
                    }
                    echo "Répertoire du dépôt : $WORKSPACE"
                    echo "Contexte Docker demandé : $APP_CONTEXT"
                '''
            }
        }

        stage('2. Préparation et vérification des outils') {
            steps {
                script {
                    def requiredTools = ['docker', 'python3', 'semgrep', 'trivy']
                    if (params.DEPLOY) {
                        requiredTools << 'kubectl'
                    }

                    withEnv(["REQUIRED_TOOLS=${requiredTools.join(' ')}"]) {
                        sh '''
                            set -eu
                            missing=""
                            for tool in $REQUIRED_TOOLS; do
                                if ! command -v "$tool" >/dev/null 2>&1; then
                                    missing="$missing $tool"
                                fi
                            done
                            if [ -n "$missing" ]; then
                                echo "Outils manquants pour l'utilisateur Jenkins :$missing"
                                exit 1
                            fi

                            docker info >/dev/null
                            python3 --version
                            semgrep --version
                            trivy --version | head -1

                            if [ "$DEPLOY" = "true" ]; then
                                kubectl get nodes
                                docker exec minikube sh -c 'command -v ctr >/dev/null 2>&1 || command -v docker >/dev/null 2>&1'
                            fi
                        '''
                    }
                }
            }
        }

        stage('3. Construction de l’image depuis le dépôt') {
            steps {
                sh '''
                    set -eu
                    if [ ! -f "$APP_CONTEXT/Dockerfile" ]; then
                        echo "ERREUR : aucun Dockerfile trouvé dans $APP_CONTEXT."
                        echo "Vérifie que le dépôt cloné contient bien le code source et son Dockerfile."
                        exit 1
                    fi
                    docker build --pull -t "$IMAGE" "$APP_CONTEXT"
                    docker image inspect "$IMAGE" >/dev/null
                '''
            }
        }

        stage('4. Scans de sécurité') {
            parallel {
                stage('Semgrep - SAST') {
                    steps {
                        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                            sh '''
                                set -eu
                                semgrep scan \
                                    --config p/owasp-top-ten \
                                    --config p/javascript \
                                    --config p/typescript \
                                    --config p/secrets \
                                    --exclude node_modules \
                                    --exclude frontend/dist \
                                    --metrics=off \
                                    --quiet \
                                    --json \
                                    --output "$REPORTS/semgrep.json" .
                                test -s "$REPORTS/semgrep.json"
                            '''
                        }
                    }
                }

                stage('Dependency-Check - SCA') {
                    when {
                        expression { params.RUN_DEPCHECK }
                    }
                    steps {
                        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                            script {
                                sh 'mkdir -p "$REPORTS/dc" && chmod 777 "$REPORTS/dc"'

                                // Vérifier la présence de la clé séparément :
                                // une erreur du scan ne sera pas masquée par le fallback.
                                def hasNvdKey = false
                                try {
                                    withCredentials([string(credentialsId: 'nvd-api-key', variable: 'NVD_KEY')]) {
                                        sh 'test -n "$NVD_KEY"'
                                    }
                                    hasNvdKey = true
                                } catch (Exception ignored) {
                                    echo 'Identifiant nvd-api-key absent : Dependency-Check sera lancé sans clé NVD.'
                                }

                                if (hasNvdKey) {
                                    withCredentials([string(credentialsId: 'nvd-api-key', variable: 'NVD_KEY')]) {
                                        sh '''
                                            set -eu
                                            docker run --rm \
                                                -v "$WORKSPACE:/src:ro" \
                                                -v dc-data:/usr/share/dependency-check/data \
                                                -v "$REPORTS/dc:/report:rw" \
                                                owasp/dependency-check:latest \
                                                --project JuiceShop \
                                                --scan /src \
                                                --exclude "**/node_modules/**" \
                                                --exclude "**/dist/**" \
                                                --disableNodeAudit \
                                                --nvdApiKey "$NVD_KEY" \
                                                --format JSON \
                                                --out /report
                                            test -s "$REPORTS/dc/dependency-check-report.json"
                                            cp "$REPORTS/dc/dependency-check-report.json" "$REPORTS/dependency-check.json"
                                        '''
                                    }
                                } else {
                                    sh '''
                                        set -eu
                                        docker run --rm \
                                            -v "$WORKSPACE:/src:ro" \
                                            -v dc-data:/usr/share/dependency-check/data \
                                            -v "$REPORTS/dc:/report:rw" \
                                            owasp/dependency-check:latest \
                                            --project JuiceShop \
                                            --scan /src \
                                            --exclude "**/node_modules/**" \
                                            --exclude "**/dist/**" \
                                            --disableNodeAudit \
                                            --format JSON \
                                            --out /report
                                        test -s "$REPORTS/dc/dependency-check-report.json"
                                        cp "$REPORTS/dc/dependency-check-report.json" "$REPORTS/dependency-check.json"
                                    '''
                                }
                            }
                        }
                    }
                }

                stage('Trivy - Image') {
                    steps {
                        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                            sh '''
                                set -eu
                                trivy image \
                                    --scanners vuln \
                                    --severity LOW,MEDIUM,HIGH,CRITICAL \
                                    --timeout 20m \
                                    --quiet \
                                    --format json \
                                    --output "$REPORTS/trivy.json" \
                                    "$IMAGE"
                                test -s "$REPORTS/trivy.json"
                            '''
                        }
                    }
                }
            }
        }

        stage('5. Staging local et scan dynamique ZAP') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '''
                        set -eu
                        docker network create "$NET"
                        docker run -d \
                            --name "juice-staging-$BUILD_NUMBER" \
                            --network "$NET" \
                            --network-alias juice \
                            "$IMAGE"

                        ready=0
                        for i in $(seq 1 30); do
                            if docker run --rm --network "$NET" curlimages/curl:8.10.1 \
                                -fsS http://juice:3000/rest/admin/application-version \
                                | grep -q version; then
                                ready=1
                                echo "Juice Shop est prêt (tentative $i/30)."
                                break
                            fi
                            echo "En attente de Juice Shop ($i/30)..."
                            sleep 5
                        done

                        if [ "$ready" -ne 1 ]; then
                            echo "Juice Shop n'a pas démarré. Derniers journaux :"
                            docker logs "juice-staging-$BUILD_NUMBER" 2>&1 | tail -80
                            exit 1
                        fi

                        mkdir -p "$REPORTS/zap-wrk"
                        chmod 777 "$REPORTS/zap-wrk"

                        # Les codes 1 et 2 de ZAP peuvent signaler des alertes.
                        # Le code 3 ou supérieur correspond à un échec technique.
                        set +e
                        docker run --rm \
                            --name "zap-$BUILD_NUMBER" \
                            --network "$NET" \
                            -v "$REPORTS/zap-wrk:/zap/wrk:rw" \
                            ghcr.io/zaproxy/zaproxy:stable \
                            zap-baseline.py \
                            -t http://juice:3000 \
                            -J /zap/wrk/zap.json \
                            -m 3 \
                            -I
                        zap_rc=$?
                        set -e

                        if [ "$zap_rc" -ge 3 ]; then
                            echo "ERREUR technique ZAP (code $zap_rc)."
                            exit "$zap_rc"
                        fi

                        test -s "$REPORTS/zap-wrk/zap.json" || {
                            echo "ERREUR : ZAP n'a pas produit son rapport JSON."
                            exit 1
                        }
                        cp "$REPORTS/zap-wrk/zap.json" "$REPORTS/zap.json"
                    '''
                }
            }
        }

        stage('6. Security Gate - Analyse des résultats') {
            steps {
                script {
                    def requiredReports = ['semgrep', 'trivy', 'zap']
                    if (params.RUN_DEPCHECK) {
                        requiredReports << 'dependency-check'
                    }

                    def gateCommand = "python3 ci/security_gate.py " +
                        "--reports '${env.REPORTS}' " +
                        "--baseline '${env.BASELINE_FILE}' " +
                        "--require '${requiredReports.join(',')}'"

                    if (params.RESET_BASELINE) {
                        gateCommand += " --reset-baseline"
                    }

                    def rc = sh(script: gateCommand, returnStatus: true)
                    env.GATE_RC = rc.toString()

                    if (rc == 0) {
                        echo 'Security Gate : rapports complets et politique respectée (ou baseline créée).'
                    } else if (rc == 1) {
                        echo 'Security Gate : nouvelle vulnérabilité CRITICAL ou escalade vers CRITICAL.'
                    } else {
                        echo 'Security Gate : contrôle incomplet ou erreur technique.'
                    }
                }
            }
        }

        stage('7. Module IA - Analyse complémentaire') {
            when {
                allOf {
                    expression { fileExists('ai_module/analyze.py') }
                    expression { fileExists("${env.REPORTS}/findings.json") }
                }
            }
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '''
                        set -eu
                        python3 ai_module/analyze.py \
                            --findings "$REPORTS/findings.json" \
                            --out "$REPORTS/ai_analysis.json"
                    '''
                }
            }
        }

        stage('8. Décision finale du pipeline') {
            steps {
                script {
                    if (env.GATE_RC == '1') {
                        error('PIPELINE BLOQUÉ : nouvelle vulnérabilité CRITICAL ou escalade vers CRITICAL.')
                    }
                    if (env.GATE_RC != '0') {
                        error('PIPELINE BLOQUÉ : Security Gate incomplet ou en erreur. Consulte les rapports.')
                    }
                    if (currentBuild.currentResult != 'SUCCESS') {
                        error('PIPELINE BLOQUÉ : au moins un contrôle technique ou une étape d’analyse a échoué.')
                    }
                    echo 'Tous les contrôles sont terminés avec succès.'
                }
            }
        }

        stage('9. Déploiement local sur Minikube') {
            when {
                allOf {
                    expression { params.DEPLOY }
                    expression { !params.RESET_BASELINE }
                    expression { env.GATE_RC == '0' }
                    expression { currentBuild.currentResult == 'SUCCESS' }
                }
            }
            steps {
                sh '''
                    set -eu
                    if docker exec minikube docker version >/dev/null 2>&1; then
                        echo "Runtime Minikube : Docker"
                        docker save "$IMAGE" | docker exec -i minikube docker load
                    else
                        echo "Runtime Minikube : containerd"
                        docker save "$IMAGE" | docker exec -i minikube ctr -n k8s.io images import -
                    fi
                '''

                writeFile file: 'k8s-generated.yaml', text: '''
apiVersion: v1
kind: Namespace
metadata:
  name: juice-shop
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: juice-shop
  namespace: juice-shop
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
      containers:
        - name: juice-shop
          image: pfa/juice-shop:BUILD_NUMBER_PLACEHOLDER
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 3000
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
            seccompProfile:
              type: RuntimeDefault
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
  namespace: juice-shop
spec:
  type: NodePort
  selector:
    app: juice-shop
  ports:
    - port: 3000
      targetPort: 3000
      nodePort: 30080
'''.replace('BUILD_NUMBER_PLACEHOLDER', env.BUILD_NUMBER)
                sh 'kubectl apply -f k8s-generated.yaml'
                sh 'kubectl -n "$K8S_NAMESPACE" rollout status deployment/juice-shop --timeout=180s'
                sh 'kubectl -n "$K8S_NAMESPACE" get pods,svc -o wide'
            }
        }
    }

    post {
        always {
            sh '''
                docker rm -f "juice-staging-$BUILD_NUMBER" "zap-$BUILD_NUMBER" >/dev/null 2>&1 || true
                docker network rm "$NET" >/dev/null 2>&1 || true
            '''
            archiveArtifacts(
                artifacts: 'security-reports/**/*.json,security-reports/*.json,k8s-generated.yaml',
                allowEmptyArchive: true
            )
        }
        success {
            echo 'Pipeline terminé : SUCCESS.'
        }
        unstable {
            echo 'Pipeline UNSTABLE : consulte les étapes de contrôle.'
        }
        failure {
            echo 'Pipeline FAILURE : consulte la première étape en échec et les rapports archivés.'
        }
    }
}
