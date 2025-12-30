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
                    echo '--- Generating .env file ---'
                    withCredentials([
                        string(credentialsId: 'openai-api-key', variable: 'ENV_OPENAI_KEY'),
                        string(credentialsId: 'n8n-webhook-url', variable: 'ENV_N8N_URL'),
                        string(credentialsId: 'mongodb-atlas-uri', variable: 'ENV_MONGO_URI'),
                        string(credentialsId: 'mongodb-db-name', variable: 'ENV_MONGO_DB_NAME'),
                        string(credentialsId: 'cloudflare-tunnel-token', variable: 'TOKEN_CF')
                    ]) {
                        sh """
                            echo "FLASK_ENV=production" > ./backend/.env
                            echo "OPENAI_API_KEY=${ENV_OPENAI_KEY}" >> ./backend/.env
                            echo "N8N_WEBHOOK_URL=${ENV_N8N_URL}" >> ./backend/.env
                            echo "MONGO_URI=${ENV_MONGO_URI}" >> ./backend/.env
                            echo "MONGO_DB_NAME=${ENV_MONGO_DB_NAME}" >> ./backend/.env
                            echo "SAVE_OUTPUTS=false" >> ./backend/.env
                            echo "OUTPUT_DIR=./outputs" >> ./backend/.env
                        """
                    }
                    echo '--- Deploying with Docker Compose ---'
                    
                    sh "docker rm -f loganalyze_be || true"
                    sh "docker rm -f loganalyze_fe || true"
                    // Tắt container cũ
                    sh "docker-compose down || true"

                    sh """
                        export CF_TUNNEL_TOKEN=${TOKEN_CF}
                        docker-compose up -d
                    """
                    // Dọn dẹp image rác
                    sh "docker image prune -f"
                }
            }
        }
    }
}