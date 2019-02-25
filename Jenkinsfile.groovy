@Library("N1Pipeline@0.0.23")
import com.n1analytics.git.GitUtils
import com.n1analytics.git.GitCommit
import com.n1analytics.maven.MavenUtils

// default git context we are using with N1 projects.
GIT_CONTEXT = "jenkins"


node() {

  // Knowing this git commit will enable us to send to github the corresponding status.
  GitCommit gitCommit = GitUtils.checkoutFromSCM(this)
  gitCommit.setInProgressStatus(GIT_CONTEXT)
  
  // Because we are providing a git commit to the maven utilities, it will report to it a failure if it happens.
  // All the configuration files (e.g.: maven, node, aws token)  are already provided by the library.
  MavenUtils mavenUtils = new MavenUtils(this, gitCommit, GIT_CONTEXT)
  
  stage("Clean") {
    mavenUtils.mavenClean()
  }
  
  stage("Compile") {
    mavenUtils.mavenCompile()
  }
  
  stage("Compile test") {
    mavenUtils.mavenCompileTest()
  }
  
  stage("Unit tests") {
    mavenUtils.mavenTest()
  }
  
  stage("Package") {
    mavenUtils.mavenPackage()
  }
  
  
//  if (env.BRANCH_NAME == "develop") {
//    stage("deploy") {
//      mavenUtils.mavenDeploy()
//    }
//  }
  
  // And finally send the success status to github.
  gitCommit.setSuccessStatus(GIT_CONTEXT)

}
