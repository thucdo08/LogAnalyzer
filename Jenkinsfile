pipeline {
    agent any

    environment {
        // ID Credential trong Jenkins
        REGISTRY_CRED = 'docker-hub-credentials'
        
        // Tên Image gốc
        IMAGE_NAME_BE = 'loganalyze-backend'
        IMAGE_NAME_FE = 'loganalyze-frontend'
    }

    stages {
        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }

        stage('Build Docker Images') {
            steps {
                script {
                    echo '--- Building Backend ---'
                    sh "docker build -t ${IMAGE_NAME_BE}:latest ./backend"

                    echo '--- Building Frontend ---'
                    sh "docker build -t ${IMAGE_NAME_FE}:latest ./frontend"
                }
            }
        }

        stage('Push to Docker Hub') {
            steps {
                script {
                    withCredentials([usernamePassword(credentialsId: REGISTRY_CRED, usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                        sh 'echo $DOCKER_PASS | docker login -u $DOCKER_USER --password-stdin'
                        
                        sh "docker tag ${IMAGE_NAME_BE}:latest ${DOCKER_USER}/${IMAGE_NAME_BE}:latest"
                        sh "docker tag ${IMAGE_NAME_FE}:latest ${DOCKER_USER}/${IMAGE_NAME_FE}:latest"

                        sh "docker push ${DOCKER_USER}/${IMAGE_NAME_BE}:latest"
                        sh "docker push ${DOCKER_USER}/${IMAGE_NAME_FE}:latest"
                    }
                }
            }
        }

        stage('Deploy (Localhost)') {
            steps {
                script {
                    echo '--- Deploying with Docker Compose ---'
                    
                    // Tắt container cũ
                    sh "docker-compose down || true"
                    
                    sh "docker-compose up -d"
                    
                    // Dọn dẹp image rác
                    sh "docker image prune -f"
                }
            }
        }
    }
}