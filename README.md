Web Application Penetration Testing

### Python-Based Web Application Security Assessment Tool

A lightweight web application security assessment tool developed using **Python, HTML, and CSS**. The project focuses on identifying common web security weaknesses through basic, non-invasive security checks and presenting the findings in an easy-to-understand dashboard.

---

## Overview

Web applications are widely used for online services, communication, business operations, and data management. However, improper security configurations and weaknesses in application design can expose websites to potential cyber threats.

This project aims to develop a simple Web Application Penetration Testing tool that performs basic security assessments on authorized web applications. It examines HTTPS usage, HTTP security headers, cookie security attributes, and HTML form information.

The tool processes the target website's HTTP response using Python and presents the assessment results through a simple web-based interface.

## Objectives

- Identify basic web application security misconfigurations.
- Evaluate the presence of important HTTP security headers.
- Examine cookie security attributes.
- Check whether a website uses HTTPS.
- Analyze basic HTML form information.
- Present security findings with severity classifications.
- Provide recommendations for improving web application security.
- Generate downloadable security assessment reports.

Key Features

1. HTTPS Assessment
- Checks whether the target website uses HTTPS.
- Identifies when the final response URL uses unencrypted HTTP.

2. HTTP Security Header Analysis
- Checks Content-Security-Policy.
- Checks Strict-Transport-Security.
- Checks X-Content-Type-Options.
- Checks X-Frame-Options.
- Checks Referrer-Policy.

3. Cookie Security Analysis
- Examines Secure attributes.
- Examines HttpOnly attributes.
- Examines SameSite attributes.

4. HTML Form Analysis
- Counts HTML forms.
- Identifies password input fields.
- Provides recommendations for manual security assessment.

5. Vulnerability Assessment Dashboard
- Displays identified security observations.
- Categorizes findings by severity.
- Presents recommendations for improving security.

6. Report Generation
- Generates a downloadable security assessment report.
- Includes observations, severity levels, and recommendations.

Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend processing and security checks |
| HTML | Web interface |
| CSS | Dashboard styling |
| Python Standard Library | HTTP server and request handling |

No external web framework is required.

## Project Architecture

The application follows a simple client-server architecture.

1. The user enters an authorized target website URL.
2. The HTML interface submits the URL to the Python application.
3. Python performs basic security checks.
4. The scanning module evaluates HTTP responses and page information.
5. The results are classified according to severity.
6. The dashboard displays the assessment findings.
7. A downloadable report is generated.

## Project Structure

```text
Web-Application-Penetration-Testing/
│
├── main.py
├── scanner.py
│
├── templates/
│   ├── index.html
│   └── results.html
│
├── static/
│   └── style.css
│
├── README.md
└── requirements.txt
```

## Installation and Execution

### Prerequisites

- Python 3.x
- A modern web browser
- Windows or Linux operating system

### Step 1: Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/web-application-penetration-testing.git
```

### Step 2: Open the project directory

```bash
cd web-application-penetration-testing
```

### Step 3: Run the application

```bash
python main.py
```

### Step 4: Open the application

Visit the following address in your browser:

```text
http://127.0.0.1:8000
```

Enter an authorized website URL and start the security assessment.

## Expected Output

The application provides:

- Website security assessment results.
- HTTPS status.
- HTTP security header observations.
- Cookie security observations.
- HTML form information.
- Severity classifications.
- Security recommendations.
- Downloadable assessment report.

## Limitations

This project is designed as a basic educational security assessment tool.

- It does not perform a complete penetration test.
- It does not exploit vulnerabilities.
- It does not perform authenticated testing.
- It does not automatically crawl an entire website.
- It does not prove SQL injection or XSS vulnerabilities.
- Its findings require manual validation.

## Future Enhancements

- Advanced SQL injection assessment in a controlled environment.
- Cross-Site Scripting (XSS) testing.
- Authentication and session security analysis.
- Website crawling and endpoint discovery.
- Improved vulnerability classification.
- PDF report generation.
- Enhanced security dashboard.

## Ethical Considerations

This tool is intended for educational purposes and authorized security assessments only.

Users must obtain explicit permission before testing any website or web application. Unauthorized scanning or testing may violate applicable laws and policies.

## Conclusion

The project demonstrates how Python can be used to develop a lightweight web application security assessment system. By combining basic security checks with an understandable dashboard and reporting functionality, it provides a foundation for learning web application security and penetration testing concepts.

---

**Developed as a Cybersecurity Project**

**Technologies:** Python | HTML | CSS
