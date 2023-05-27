# HARAnalyzer: Unleash the Power of Network Call Insights for Unbeatable Web Performance


Harness the untapped potential of your website's network calls with HARAnalyzer, the ultimate tool for unlocking unparalleled web performance. Analyze HTTP Archive (HAR) files and dive deep into the intricacies of network requests made to internal APIs. 

HARAnalyzer is a powerful tool designed to analyze HTTP Archive (HAR) files, which capture network traffic data of a web application. It provides technical insights and comprehensive information about the network calls made by a website to its internal APIs

## Possible use cases


🚀 **Supercharge Performance**: Optimize your web application by pinpointing performance bottlenecks, slow-loading resources, and inefficient API calls. Maximize user satisfaction and skyrocket conversion rates.

🔒 **Bulletproof Security**: Ensure the security of your API interactions with intelligent security auditing. Detect vulnerabilities, enforce compliance, and protect sensitive data from prying eyes.

📊 **Smart Analytics**: Uncover hidden patterns, gain deep insights, and track API usage trends with powerful analytics capabilities. Leverage advanced visualization and machine learning to drive data-informed decisions.

🔧 **Effortless Troubleshooting**: Debug with ease using advanced troubleshooting and error monitoring features. Quickly identify root causes, reduce downtime, and keep your web application running flawlessly.

📚 **Automated Documentation**: Say goodbye to manual documentation efforts. Automatically generate comprehensive API documentation, saving time and ensuring accuracy. Focus on what matters – building great products.

## Installation

HARAnalyzer can be installed via pip. Before starting the installation, ensure that pip is installed on your system. If it's not, you can download Python and pip from [here](https://www.python.org/downloads/).

To install HARAnalyzer, open your terminal and type the following command:

```
pip install haranalyzer
```

This will install HARAnalyzer along with its dependencies. After the installation is completed, you can start using HARAnalyzer in your Python scripts.

## Examples

Here are three examples of how to use HARAnalyzer:

### Example 1: Basic usage

```
from haranalyzer import HARAnalyzer
```

# Initialize the analyzer with your .har file and the main website URL
```
analyzer = HARAnalyzer(har_file_path='path_to_your_file.har', main_website='https://www.your-website.com')
```

# Extract API calls

```
api_calls = analyzer.analyze()
```

# Print API calls

```
for call in api_calls:
    print(call)
```

### Example 2: Using strict authentication mode

```
from haranalyzer import HARAnalyzer
```

# Initialize the analyzer with your .har file, the main website URL, and set auth_mode to 'strict'

```
analyzer = HARAnalyzer(har_file_path='path_to_your_file.har', main_website='https://www.your-website.com', auth_mode='strict')
```

# Extract API calls

```
api_calls = analyzer.analyze()
```

# Print API calls

```
for call in api_calls:
    print(call)
```

### Example 3: Saving output to a file

```
from haranalyzer import HARAnalyzer
```

# Initialize the analyzer with your .har file and the main website URL

```
analyzer = HARAnalyzer(har_file_path='path_to_your_file.har', main_website='https://www.your-website.com')
```

# Extract API calls

```
api_calls = analyzer.analyze()
```

# Save the output to a file

```
analyzer.save_output_to_file(output_path='path_to_your_output_file.json', entries=api_calls)
```

