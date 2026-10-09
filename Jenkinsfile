pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'docker pull bkimminich/juice-shop:latest'
                sh 'docker tag bkimminich/juice-shop:latest juice-shop:v1'
            }
        }
        stage('Verify') {
            steps {
                sh 'docker images | grep juice-shop'
            }
        }
        stage('Scan Code - Semgrep') {
            steps {
                sh 'docker run --rm -v "$PWD":/src semgrep/semgrep semgrep scan --config=auto --severity ERROR'
            }
        }
        stage('Scan Image - Trivy') {
            steps {
                sh 'docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --severity HIGH,CRITICAL --no-progress juice-shop:v1'
            }
        }
        stage('Deploy') {
            steps {
                sh 'minikube image load juice-shop:v1'
                sh 'kubectl delete deployment juice-shop-k8s --ignore-not-found=true'
                sh 'kubectl create deployment juice-shop-k8s --image=juice-shop:v1'
                sh 'kubectl expose deployment juice-shop-k8s --type=NodePort --port=3000 || true'
                sh 'kubectl rollout status deployment/juice-shop-k8s --timeout=180s'
                sh 'kubectl get pods'
            }
        }
        stage('Test dynamique - OWASP ZAP') {
            steps {
                sh '''
                    NODEPORT=$(kubectl get svc juice-shop-k8s -o jsonpath='{.spec.ports[0].nodePort}')
                    MINIKUBE_IP=$(minikube ip)
                    mkdir -p reports && chmod 777 reports
                    docker run --rm -v "$PWD/reports":/zap/wrk:rw zaproxy/zap-stable zap-baseline.py -t http://$MINIKUBE_IP:$NODEPORT -r zap-report.html || true
                '''
            }
        }
        stage('Scan Dependances - Dependency-Check') {
            steps {
                sh '''
                    mkdir -p reports && chmod 777 reports
                    docker run --rm -v "$PWD":/src -v "$PWD/reports":/report -v dc-data:/usr/share/dependency-check/data owasp/dependency-check:latest --scan /src --format HTML --out /report --disableNodeAudit --disableYarnAudit || true
                '''
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
    }
}
