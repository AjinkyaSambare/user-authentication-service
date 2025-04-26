/**
 * This script creates multiple placeholder issues in the repository
 * to simulate a real-world project with many issues.
 * 
 * Note: This is just for demonstration purposes.
 */

const https = require('https');
const fs = require('fs');

// Configuration
const owner = 'AjinkyaSambare';
const repo = 'user-authentication-service';
const token = process.env.GITHUB_TOKEN;

// Issue templates
const issueTypes = [
  { title: 'Add password reset functionality', body: 'Implement password reset feature via email', labels: ['enhancement'] },
  { title: 'Implement rate limiting', body: 'Add rate limiting to protect against brute force attacks', labels: ['enhancement', 'security'] },
  { title: 'Improve error handling', body: 'Make error messages more descriptive and consistent', labels: ['enhancement'] },
  { title: 'Add account lockout after failed attempts', body: 'Lock user accounts after multiple failed login attempts', labels: ['enhancement', 'security'] },
  { title: 'Update documentation', body: 'Update API documentation with latest endpoints', labels: ['documentation'] },
  { title: 'Fix validation in user model', body: 'Email validation regex needs improvement', labels: ['bug'] },
  { title: 'Add user profile endpoints', body: 'Create endpoints for updating user profile information', labels: ['enhancement'] },
  { title: 'Add 2FA support', body: 'Implement two-factor authentication using time-based one-time passwords', labels: ['enhancement', 'security'] }
];

// Function to create an issue
function createIssue(issueData) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({
      title: issueData.title,
      body: issueData.body,
      labels: issueData.labels
    });

    const options = {
      hostname: 'api.github.com',
      path: `/repos/${owner}/${repo}/issues`,
      method: 'POST',
      headers: {
        'User-Agent': 'Node.js',
        'Content-Type': 'application/json',
        'Authorization': `token ${token}`,
        'Content-Length': data.length
      }
    };

    const req = https.request(options, (res) => {
      let responseData = '';
      
      res.on('data', (chunk) => {
        responseData += chunk;
      });
      
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(JSON.parse(responseData));
        } else {
          reject(new Error(`Status Code: ${res.statusCode}, Body: ${responseData}`));
        }
      });
    });

    req.on('error', (error) => {
      reject(error);
    });

    req.write(data);
    req.end();
  });
}

// Main function to create issues
async function createIssues() {
  try {
    // Number of issues to create (to reach issue #42 with our bug issue)
    const numberOfIssuesToCreate = 39; // We already have 3 issues
    
    console.log(`Creating ${numberOfIssuesToCreate} issues...`);
    
    for (let i = 0; i < numberOfIssuesToCreate; i++) {
      // Select a random issue type
      const issueType = issueTypes[Math.floor(Math.random() * issueTypes.length)];
      
      // Create the issue
      const issue = await createIssue({
        title: `${issueType.title} - ${i + 4}`,
        body: issueType.body,
        labels: issueType.labels
      });
      
      console.log(`Created issue #${issue.number}: ${issue.title}`);
      
      // Add a small delay to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    console.log('All issues created successfully!');
  } catch (error) {
    console.error('Error creating issues:', error);
  }
}

// Run the script
createIssues();
