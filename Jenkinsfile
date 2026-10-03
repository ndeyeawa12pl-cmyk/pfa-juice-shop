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
    }
}
