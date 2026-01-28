pipeline {
    agent any

    environment {
        // Docker Hub credentials
        REGISTRY_CRED = 'docker-hub-credentials'
        DOCKER_USER = 'dhuuthuc'
        
        // Image names
        IMAGE_NAME_BE = 'loganalyze-backend'
        IMAGE_NAME_FE = 'loganalyze-frontend'
        
        // App server details
        APP_SERVER = '54.254.11.86'
        SSH_CRED = 'app-server-ssh'
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
                    sh "docker build -t ${IMAGE_NAME_BE}:${BUILD_NUMBER} ./backend"
                    sh "docker tag ${IMAGE_NAME_BE}:${BUILD_NUMBER} ${IMAGE_NAME_BE}:latest"

                    echo '--- Building Frontend ---'
                    sh "docker build -t ${IMAGE_NAME_FE}:${BUILD_NUMBER} ./frontend"
                    sh "docker tag ${IMAGE_NAME_FE}:${BUILD_NUMBER} ${IMAGE_NAME_FE}:latest"
                }
            }
        }

        stage('Push to Docker Hub') {
            steps {
                script {
                    withCredentials([usernamePassword(credentialsId: REGISTRY_CRED, usernameVariable: 'DOCKER_USERNAME', passwordVariable: 'DOCKER_PASSWORD')]) {
                        sh 'echo $DOCKER_PASSWORD | docker login -u $DOCKER_USERNAME --password-stdin'
                        
                        // Tag with username
                        sh "docker tag ${IMAGE_NAME_BE}:${BUILD_NUMBER} ${DOCKER_USER}/${IMAGE_NAME_BE}:${BUILD_NUMBER}"
                        sh "docker tag ${IMAGE_NAME_BE}:latest ${DOCKER_USER}/${IMAGE_NAME_BE}:latest"
                        sh "docker tag ${IMAGE_NAME_FE}:${BUILD_NUMBER} ${DOCKER_USER}/${IMAGE_NAME_FE}:${BUILD_NUMBER}"
                        sh "docker tag ${IMAGE_NAME_FE}:latest ${DOCKER_USER}/${IMAGE_NAME_FE}:latest"

                        // Push to Docker Hub
                        sh "docker push ${DOCKER_USER}/${IMAGE_NAME_BE}:${BUILD_NUMBER}"
                        sh "docker push ${DOCKER_USER}/${IMAGE_NAME_BE}:latest"
                        sh "docker push ${DOCKER_USER}/${IMAGE_NAME_FE}:${BUILD_NUMBER}"
                        sh "docker push ${DOCKER_USER}/${IMAGE_NAME_FE}:latest"
                    }
                }
            }
        }

        stage('Deploy to AWS') {
            steps {
                script {
                    echo '--- Deploying to App Server ---'
                    
                    sshagent([SSH_CRED]) {
                        // Create .env file on remote server
                        withCredentials([
                            string(credentialsId: 'openai-api-key', variable: 'OPENAI_KEY'),
                            string(credentialsId: 'mongodb-uri', variable: 'MONGO_URI'),
                            string(credentialsId: 'mongodb-db-name', variable: 'MONGO_DB')
                        ]) {
                            sh """
                                ssh -o StrictHostKeyChecking=no ubuntu@${APP_SERVER} '
                                    # Create app directory
                                    mkdir -p /opt/loganalyzer
                                    cd /opt/loganalyzer
                                    
                                    # Create .env file
                                    cat > .env << EOF
FLASK_ENV=production
OPENAI_API_KEY=${OPENAI_KEY}
MONGO_URI=${MONGO_URI}
MONGO_DB_NAME=${MONGO_DB}
SAVE_OUTPUTS=false
OUTPUT_DIR=/app/outputs
EOF
                                    
                                    # Create docker-compose.yml
                                    cat > docker-compose.yml << EOF
version: "3.8"

services:
  backend:
    image: ${DOCKER_USER}/${IMAGE_NAME_BE}:latest
    container_name: loganalyze_backend
    restart: always
    ports:
      - "8000:8000"
    env_file:
      - .env
    networks:
      - app-network

  frontend:
    image: ${DOCKER_USER}/${IMAGE_NAME_FE}:latest
    container_name: loganalyze_frontend
    restart: always
    ports:
      - "3000:80"
    depends_on:
      - backend
    networks:
      - app-network

networks:
  app-network:
    driver: bridge
EOF
                                    
                                    # Pull latest images
                                    docker-compose pull
                                    
                                    # Stop and remove old containers
                                    docker-compose down || true
                                    
                                    # Start new containers
                                    docker-compose up -d
                                    
                                    # Clean up old images
                                    docker image prune -f
                                '
                            """
                        }
                    }
                }
            }
        }

        stage('Verify Deployment') {
            steps {
                script {
                    echo '--- Verifying deployment ---'
                    sshagent([SSH_CRED]) {
                        sh """
                            ssh -o StrictHostKeyChecking=no ubuntu@${APP_SERVER} '
                                cd /opt/loganalyzer
                                docker-compose ps
                                echo "---"
                                echo "Backend health check:"
                                curl -s http://localhost:8000/api/health || echo "Backend not ready yet"
                            '
                        """
                    }
                }
            }
        }
    }

    post {
        always {
            echo '--- Cleaning up local images ---'
            sh "docker image prune -f || true"
        }
        success {
            echo '✅ Deployment successful!'
            echo "Application URL: http://${APP_SERVER}"
            echo "API URL: http://${APP_SERVER}:8000"
        }
        failure {
            echo '❌ Deployment failed!'
        }
    }
}