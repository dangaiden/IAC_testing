# Vulnerable Lambda Function - Maven Build Instructions

## Project Structure
```
vulnerable-lambda/
├── pom.xml
├── src/
│   └── main/
│       └── java/
│           └── com/
│               └── example/
│                   └── lambda/
│                       └── VulnerableLambdaFunction.java
```

## Prerequisites
- Java 11 or higher
- Maven 3.6 or higher

Check if you have Maven installed:
```bash
mvn --version
```

If not installed, download from: https://maven.apache.org/download.cgi

## Setup Instructions

1. Create the directory structure:
```bash
mkdir -p vulnerable-lambda/src/main/java/com/example/lambda
```

2. Place the files:
   - Put `pom.xml` in `vulnerable-lambda/`
   - Put `VulnerableLambdaFunction.java` in `vulnerable-lambda/src/main/java/com/example/lambda/`

3. Navigate to project directory:
```bash
cd vulnerable-lambda
```

## Build Commands

### Clean and compile:
```bash
mvn clean compile
```

### Create JAR with all dependencies (recommended):
```bash
mvn clean package
```

This creates: `target/vulnerable-lambda-1.0-SNAPSHOT.jar`

### Skip tests (if any):
```bash
mvn clean package -DskipTests
```

## Deploy to AWS Lambda

1. Upload the JAR file from `target/vulnerable-lambda-1.0-SNAPSHOT.jar`
2. Set the handler to: `com.example.lambda.VulnerableLambdaFunction::handleRequest`
3. Set runtime to: Java 11

## Testing Input Format

```json
{
  "userId": "123",
  "action": "execute",
  "command": "ls -la",
  "xmlData": "<?xml version=\"1.0\"?>...",
  "filePath": "../../../etc/passwd",
  "url": "http://169.254.169.254/latest/meta-data/",
  "password": "test123"
}
```

## WARNING
⚠️ This code is DELIBERATELY VULNERABLE for security testing purposes only.
DO NOT deploy to production environments!