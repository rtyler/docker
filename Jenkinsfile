#!/usr/bin/env groovy

pipeline {
  agent none
  stages {
    stage('Build Linux') {
      agent { label 'linux' }
      steps {
        echo "Building on Linux first to ensure we haven't broken anything"
        sh 'make'
      }
    }
    stage('Build FreeBSD') {
      agent { label 'freebsd' }
      steps {
        sh 'AUTO_GOPATH=1 ./hack/make.sh binary'
      }
    }
  }
}
