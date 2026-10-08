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
                sh 'kubectl get pods'
            }
        }
    }
}
