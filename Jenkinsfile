// Self-hosted equivalent of the GitHub Actions pipeline, for on-prem Jenkins.
//
// Fixes over the original v1 pipeline (kept in git history on purpose):
//  - secrets come from the Jenkins credentials store via withCredentials, are
//    masked in logs and never interpolated by Groovy (single-quoted sh blocks);
//    the old version took the SonarQube password as a build *parameter* and
//    interpolated it into a double-quoted shell string;
//  - security gates actually gate: the old Snyk step ended with `|| true`,
//    which silently disabled its own severity threshold;
//  - Jenkinsfile and code come from the same commit (multibranch), instead of
//    a "branch" parameter that ran main's pipeline against another branch;
//  - images are tagged with the commit SHA (immutable, traceable, rollback-able),
//    scanned before push, and deployed by digest.

pipeline {
  agent { label 'docker' }

  options {
    timeout(time: 30, unit: 'MINUTES')
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '20'))
    timestamps()
  }

  environment {
    IMAGE    = 'ghcr.io/azog1812/web-app'
    TAG      = "${env.GIT_COMMIT?.take(12) ?: 'dev'}"
    NODE_IMG = 'node:24-trixie-slim'
  }

  stages {
    stage('Secret scan') {
      steps {
        sh 'docker run --rm -v "$PWD:/repo" ghcr.io/gitleaks/gitleaks:latest detect --source=/repo --redact --exit-code 1'
      }
    }

    stage('Install, lint, test') {
      agent { docker { image "${NODE_IMG}"; reuseNode true } }
      steps {
        sh '''
          npm ci --ignore-scripts
          npm run lint
          npm run typecheck
          npm run test:coverage
          npm audit --omit=dev --audit-level=high
          npm audit signatures
        '''
      }
      post {
        always { archiveArtifacts artifacts: 'coverage/lcov.info', allowEmptyArchive: true }
      }
    }

    stage('SAST (Semgrep)') {
      steps {
        sh '''
          docker run --rm -v "$PWD:/src" semgrep/semgrep:latest \
            semgrep scan --config p/owasp-top-ten --config p/nodejs --config p/typescript \
            --config .semgrep/ --error --metrics=off
        '''
      }
    }

    stage('SonarQube') {
      when { expression { return env.SONAR_ENABLED == 'true' } }
      steps {
        withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
          // Single quotes: the shell expands $SONAR_TOKEN, Groovy never sees it.
          sh '''
            docker run --rm -e SONAR_TOKEN -e SONAR_HOST_URL="$SONAR_HOST_URL" \
              -v "$PWD:/usr/src" sonarsource/sonar-scanner-cli:latest \
              -Dsonar.projectKey=bastion -Dsonar.qualitygate.wait=true
          '''
        }
      }
    }

    stage('IaC & Dockerfile lint') {
      steps {
        sh 'docker run --rm -i hadolint/hadolint:latest < Dockerfile'
        sh 'docker run --rm -v "$PWD:/src" bridgecrew/checkov:latest -d /src/deploy --framework kubernetes --quiet'
      }
    }

    stage('Build image') {
      steps {
        sh 'docker build --pull -t "$IMAGE:$TAG" .'
      }
    }

    stage('Image scan (Trivy)') {
      steps {
        sh '''
          docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image \
            --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$IMAGE:$TAG"
        '''
      }
    }

    stage('Push & sign') {
      when { branch 'main' }
      steps {
        withCredentials([
          usernamePassword(credentialsId: 'ghcr', usernameVariable: 'REG_USER', passwordVariable: 'REG_TOKEN'),
          file(credentialsId: 'cosign-key', variable: 'COSIGN_KEY'),
          string(credentialsId: 'cosign-password', variable: 'COSIGN_PASSWORD'),
        ]) {
          sh '''
            echo "$REG_TOKEN" | docker login ghcr.io -u "$REG_USER" --password-stdin
            docker push "$IMAGE:$TAG"
            DIGEST=$(docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE:$TAG")
            cosign sign --yes --key "$COSIGN_KEY" "$DIGEST"
            echo "$DIGEST" > image-digest.txt
          '''
        }
        archiveArtifacts artifacts: 'image-digest.txt'
      }
    }

    stage('Deploy') {
      when { branch 'main' }
      steps {
        input message: 'Deploy to production?', ok: 'Deploy'
        withCredentials([file(credentialsId: 'kubeconfig-prod', variable: 'KUBECONFIG')]) {
          sh '''
            kubectl -n bastion set image deployment/bastion bastion="$(cat image-digest.txt)"
            kubectl -n bastion rollout status deployment/bastion --timeout=120s
          '''
        }
      }
    }
  }

  post {
    always {
      sh 'docker logout ghcr.io || true'
      cleanWs()
    }
  }
}
