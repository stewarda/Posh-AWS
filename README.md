Posh-AWS:
=========

Powershell functions for management of AWS accounts and resources.

##Powershell Modules
Powershell modules provide a simple mechanism to share and use functions and scripts. There is a good article [here](https://www.simple-talk.com/sysadmin/powershell/an-introduction-to-powershell-modules/) that provides background on using modules.

##Using Powershell Modules

Download the module folder and add it to the following path: C:\Users\Username\Documents\WindowsPowerShell\Modules

You should now be able to use the following command to list available modules:

`Get-Module -ListAvailable`

 and you should now see Posh-AWS. You can import the module using:

`Import-Module Posh-AWS -verbose`

To list all the functions available in Posh-AWS enter:

`Get-Commands -Module Posh-AWS`

##List of Posh-AWS Functions and Help

| CommandType   |  Name               |
| ------------- |:--------------------|
|Function       |Add-AWSIngressRule   |
|Function       |Find-AWSEC2Instance  |
|Function       |Find-AWSIAMUser      |
|Function       |Get-AWSAccountInformation |
|Function       |Get-AWSEC2Instances |
|Function       |Get-AWSELBs         |
|Function       |Get-AWSIAMGroups    |
|Function       |Get-AWSIAMPasswordPolicy |
|Function       |Get-AWSIAMUsers        |
|Function       |Get-AWSIngressRules    |
|Function       |Get-AWSRDSInstances    |
|Function       |Get-AWSSubnets         |
|Function       |Get-SSLCertificate     |
|Function       |Import-AWSProfiles     |
|Function       |Invoke-TrustedAdvisorChecks |
|Function       |New-AWSIAMGroup     |
|Function       |New-AWSIAMUser       |
|Function       |New-ComplexPassword  |
|Function       |Remove-AWSIAMGroup  |
|Function       |Remove-AWSIAMUser     |
|Function       |Revoke-AMIPermissions   |
|Function       |Set-AWSIAMPasswordPolicy |
|Function       |Update-AWSIAMUser       |

Each function has its own help documentation which can be accessed as follows (using Add-AWSIngressRule as an example)

`Get-Help Add-AWSIngressRule`

There are 3 help switches available

To see the examples, type: `get-help Get-AWSIngressRules -examples`
For more information, type: `get-help Get-AWSIngressRules -detailed`
For technical information, type: `get-help Get-AWSIngressRules -full`

##Common Paramaters and PS Profiles/Credentials

Most functions within the module have parameters for:

`-ProfileName`    (this allows you to simply enter the name of a profile containing AWS key pairs and pass them with the command)
`-Region`       (the name of the AWS region for which the command is being executed)

More information about the use of powershell profiles for credential management can be found [here](http://docs.aws.amazon.com/powershell/latest/userguide/specifying-your-aws-credentials.html)

The real benefit of these profiles is that it makes it very easy to manage access to large numbers of AWS accounts, for example:

````
$AWSCredentials = Get-AWSCredentials -ListProfiles
foreach ($AWSCredential in $AWSCredentials)
{
    <Do stuff> -ProfileName $AWSCredential
}
````

In general the stored profiles should be used and then removed from the Powershell profile once you are finished using them. To facilitate this there is a function ``Import-AWSProfiles`` that allows you to import credentials easily, especially when you have a large number to manage. You can simply import from .csv allowing you to store a .csv document (in password vault with encryption) more securely.

Once you have finished using credentials, you can remove them from the profile using ``get-AWScredentials -listprofiles | Clear-AWSCredentials``

##IAM Permissions
To use these functions it is assumed that you have IAM keys that provide Full Access to all AWS services. Many of the functions provide the ability to manage critical services (IAM/EC2/Trusted Advisor). In addition almost all functions require at least read-access for IAM (which is not typical for most users) in order to allow the function to confirm the AWS account number (since there are no other native mechanisms to do this)

##To Do
Add the following functions:

  Add-AMIPermissions
  Add-AWSEgressRule​
  Get-AWSEgressRules
  Update-AWSIAMGroup

