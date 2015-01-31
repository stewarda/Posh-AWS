<#
.SYNOPSIS
    Finds unused EC2 security groups.
.DESCRIPTION
    Searches EC2 security groups for a given region and finds any that are highly likely to not be in use. For eacg security group in the region checks to see whether the group contains any EC2 instances, whether it is associated with any ELB or whether its used by any RDS instance.
.PARAMETER Region
    The AWS region to check for empty security groups. 
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns $EmptyGroups which is an array of PS objects containing the following information:
    AWSAccountNumber:       The AWS account number that contains the EC2 security group.
    AWSAccountName:         The AWS account name that contains the EC2 security group.
    AWSRegion:              The AWS region containing the EC2 security group.
    GroupName:              The name of the EC2 security group.
    GroupID:                The ID of the EC2 security group.
    VPCID:                  The VPCID of the EC2 security group.
    InstancesinGroup:       The number of EC2 instances that are members of the EC2 security group.
    RDSGroup:               Whether the EC2 security group is used by an RDS instance (TRUE/FALSE)
    ELBGroup:               Whether the EC2 security group is used by an ELB (TRUE/FALSE)
.NOTES
    NAME......:  Get-UnusedSecurityGroups
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    Get-UnusedSecurityGroups -Region 'us-east-1'
    Checks EC2 security groups in the region 'us-east-1' to find any groups that are likely not in use by checking whether the group is used by any EC2 instance, ELB or RDS instance. 
#>
function Get-UnusedSecurityGroups
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true,HelpMessage="The system name of the AWS region in which the operation should be invoked. For example: us-east-1")]
        [ValidateSet("us-east-1","us-west-1","us-west-2","eu-west-1","eu-central-1","ap-northeast-1","ap-southeast-1","ap-southeast-2","sa-east-1")] 
        [String]
        $Region,

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    ) 

    # Return variable containing all security groups for a given region.
    $SecurityGroups = Get-EC2SecurityGroup -Region $Region -Profile $ProfileName

    if ($SecurityGroups)
    {
        write-verbose "Found $($SecurityGroups.count) Security Groups in Region: $Region"
        
        # Empty array used to contain PS objects with information about empty groups
        $EmptyGroups = @()

        foreach ($SecurityGroup in $SecurityGroups)
        {
            $NumberInstancesinGroup = ((get-ec2instance -region $region -ProfileName $ProfileName).instances | where { $($_.securitygroups).GroupName -eq "$($SecurityGroup.GroupName)" } ).count
           
            if ($NumberInstancesinGroup -eq 0)
            {
                write-verbose "Security Group: $($SecurityGroup.GroupName) ($($SecurityGroup.GroupID)) does not contain instances."
            }

            else
            {
                write-verbose "Security Group: $($SecurityGroup.GroupName) ($($SecurityGroup.GroupID)) contains: $NumberInstancesinGroup instances."
            }

            if (!(Get-ELBLoadBalancer -region $region -ProfileName $ProfileName | select -expand sourcesecuritygroup | where { $_.groupname -eq $($SecurityGroup.GroupName) } ))
            {
                write-verbose "Security Group: $($SecurityGroup.GroupName) ($($SecurityGroup.GroupID)) is not used by ELBs."
                $ELBGroup = 'FALSE'
            }

            else 
            {
               write-verbose "Security Group: $($SecurityGroup.GroupName) ($($SecurityGroup.GroupID)) is used by ELB"
               $ELBGroup = 'TRUE'
            }

            if (!($(Get-RDSDBInstance -region $region -ProfileName $ProfileName).VpcSecurityGroups | where { $_.VpcSecurityGroupId -eq $($SecurityGroup.GroupID) } ))
            {
                write-verbose "Security Group: $($SecurityGroup.GroupName) ($($SecurityGroup.GroupID)) is not used by RDS."
                $RDSGroup = 'FALSE'                
            }

            else 
            {
                write-verbose "Security Group: $($SecurityGroup.GroupName) ($($SecurityGroup.GroupID)) is used by RDS."
                $RDSGroup = 'TRUE'                
            }

            $VPCID = $($SecurityGroup.VPCID)

            if (!($VPCID))
            {
                $VPCID = 'NONE'
            }

            # Return AWS account number from account
            $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
            $AccountNumber = $Matches[0]

            # Create object, populate information return from function
            $EmptyGroup = [ordered]  @{
                                AWSAccountNumber="$AccountNumber";
                                AWSAccountName="$ProfileName";
                                AWSRegion="$Region";       
                                GroupName="$($SecurityGroup.GroupName)";  
                                GroupID="$($SecurityGroup.GroupId)";
                                VPCID="$VPCID"
                                InstancesInGroup="$NumberInstancesinGroup"
                                ELBGroup="$ELBGroup";
                                RDSGroup="$RDSGroup"
                                } 

            $EmptyGroupGroupobject = New-Object -Type PSObject -Prop $EmptyGroup
            $EmptyGroups += $EmptyGroupGroupobject
        }

        $EmptyGroups
    }

    else 
    {
        
        write-verbose "No Security Groups Found in region: $region" 
         
    } 
}
<#
.SYNOPSIS
    Finds open EC2 security groups.
.DESCRIPTION
    Queries Trusted Advisor to find security groups that have rules allowing access from 0.0.0.0/0. Trusted Advisor is not a region specific service, so information is for all regions in the AWS account.
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns $OpenGroups which is an array of PS objects containing the following information:
    AWSAccountNumber:       The AWS account number that contains the EC2 security group.
    AWSAccountName:         The AWS account name that contains the EC2 security group.
    AWSRegion:              The AWS region containing the EC2 security group.
    GroupName:              The name of the EC2 security group.
    GroupID:                The ID of the EC2 security group.
    VPCID:                  The VPCID of the EC2 security group.
    Protocol:               The protocol for the open rule in the EC2 security group.
    Port:                   The port of the open rule in the EC2 security group.
    SourceIP:               The source IP for the open rule (will be 0.0.0.0/0)
    InstancesinGroup:       The number of EC2 instances in the open group, this can be used to prioritise remediation
    TotalInstances:         The total number of EC2 instances in the region, used to calculate percentage of instances.
    PercentageinGroup:      The percentage of instances in the open group for the region.
.NOTES
    NAME......:  Get-OpenSecurityGroups
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    Get-OpenSecurityGroups -Region 'us-east-1'
    Checks Trusted Advisor for EC2 security groups in the region 'us-east-1' to find any groups that are likely not in use by checking whether the group is used by any EC2 instance, ELB or RDS instance.
#>
function Get-OpenSecurityGroups
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    )

    $OpenSecurityGroups = Get-ASATrustedAdvisorCheckResult -Profile $ProfileName -CheckId 1iG5NDGVre | Select -expand FlaggedResources
    $OpenGroups = @()

    if ($OpenSecurityGroups)
    {
        foreach ($OpenSecurityGroup in $OpenSecurityGroups)
        {
            $SecurityGroupInfo = $OpenSecurityGroup | select -expand metadata
            $Region = $SecurityGroupInfo[0]
            $SecurityGroupName = $SecurityGroupInfo[1]
            $SecurityGroupID = $SecurityGroupInfo[2]
            $OpenRuleProtocol = $SecurityGroupInfo[3]
            $OpenRulePort = $SecurityGroupInfo[4]
            $OpenRuleSourceIP = $SecurityGroupInfo[6]   

            if ($OpenRuleProtocol -eq "ICMP")
            {
                $OpenRulePort = '-1'
            }

            $Instances = (get-ec2instance -region $Region -ProfileName $ProfileName).instances  
            $InstancesinGroup = ($Instances | where { $($_.securitygroups).GroupName -eq "$SecurityGroupName" } ).count
            $TotalInstances = $($Instances.count)
            
            if ($InstancesinGroup -eq '0')
            {
                $PercentageinGroup = '0'
            }

            if ($TotalInstances -eq '0')
            {
                $TotalInstances = '0'
            }
            
            else 
            {
                $PercentageinGroup= $("{0:N2}" -f (($InstancesinGroup/$TotalInstances)*100) ) + " %"  
            }

            write-verbose "$SecurityGroupName is open: $OpenRuleProtocol : $OpenRulePort"
            
            # Return AWS account number from account
            $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
            $AccountNumber = $Matches[0]

            # Create object, populate information return from function            
            $OpenGroup = [ordered]  @{
                                    AWSAccountNumber="$AccountNumber";
                                    AWSAccountName="$ProfileName"; 
                                    AWSRegion="$Region";        
                                    GroupName = "$SecurityGroupName";
                                    GroupID = "$SecurityGroupID";
                                    OpenProtocol = "$OpenRuleProtocol";
                                    OpenPort = "$OpenRulePort";
                                    SourceIP = "$OpenRuleSourceIP";
                                    InstancesinGroup = "$InstancesinGroup";
                                    TotalInstances = "$TotalInstances";
                                    PercentageinGroup = "$PercentageinGroup"
                                    }

            $OpenGroupGroupobject = New-Object -Type PSObject -Prop $OpenGroup
            $OpenGroups += $OpenGroupGroupobject                                       
        }

        $OpenGroups
    }
    
    else 
    {
        write-verbose "Account contains no Open Security Groups"          
        Return
    }        
}
<#
.SYNOPSIS
    Gets RDS instance information.
.DESCRIPTION
    Returns information for RDS instances in a given AWS region.
.PARAMETER Region
    The AWS region to check for empty security groups. 
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns $AllRDSInstances which is an array of PS objects containing the following information:
    AWSAccountNumber:       The AWS account number that contains the RDS instance.
    AWSAccountName:         The AWS account name that contains the RDS instance.
    AWSRegion:              The AWS region containing the RDS instance.
    AZ:                     The name of the availability zone that the RDS instance resides in.
    DBName:                 The name of the RDS instance DB.
    DBIdentifier:           The DB identifier of the RDS instance.
    DBEngine:               The DB engine of the RDS instance.
    DBEngineVersion:        The DB engine version of the RDS instance.
    VPCSecurityGroupName:   The VPC security group name of the RDS instance.
.NOTES
    NAME......:  Get-RDSInstanceinfo
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    Get-RDSInstanceinfo -Region 'us-east-1'

#>
function Get-RDSInstances
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true,HelpMessage="The system name of the AWS region in which the operation should be invoked. For example: us-east-1")]
        [ValidateSet("us-east-1","us-west-1","us-west-2","eu-west-1","eu-central-1","ap-northeast-1","ap-southeast-1","ap-southeast-2","sa-east-1")] 
        [String]
        $Region,

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    ) 

    $AllRDSInstances = @()

    Try
    {
        $RDSInstances = Get-RDSDBInstance -Region $region -Profile $ProfileName     
        write-verbose "Found RDS instances in region: $region"
    }

    Catch
    {
        
        write-verbose "No RDS instances found in region: $region" 
        return 
    }


    foreach ($RDSInstance in $RDSInstances)
    {
        write-verbose "Found RDS instance identifier: $($RDSInstance.DBInstanceIdentifier)"
        #$VPCSecurityGroup = get-ec2securitygroup -groupID $($RDSInstance.VpcSecurityGroups.VpcSecurityGroupId) | select -expand groupname
		$DBName = $($RDSInstance.DBName)
		
		if (!($DBName))
		{
			$DBName = 'NONE'
		}
		
        # Return AWS account number from account
        $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
        $AccountNumber = $Matches[0]

        # Create object, populate information return from function

        $RDSInfo = [ordered] @{
                        AWSAccountNumber="$AccountNumber";
                        AWSAccountName="$ProfileName"; 
                        AWSRegion="$Region";
                        AZ="$($RDSInstance.AvailabilityZone)";
                        DBName="$DBName";     
                        DBIdentifier="$($RDSInstance.DBInstanceIdentifier)";
                        DBEngine="$($RDSInstance.Engine)";
                        DBEngineVersion="$($RDSInstance.EngineVersion)";
						DBSecurityGroups="$($RDSInstance.DBSecurityGroups.DBSecurityGroupName)"
                    }
            
        $RDSObj = New-Object -Type PSObject -Prop $RDSInfo                
        $AllRDSInstances += $RDSObj             
    }

    $AllRDSInstances
}
<#
.SYNOPSIS
    Gets IAM User information.
.DESCRIPTION
    Returns information for IAM users in a given AWS account. IAM is not a region specific service, so information is for the AWS account.
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns $AllIAMUsers which is an array of PS objects containing the following information:
    AWSAccountNumber:       The AWS account number that contains the IAM user.
    AWSAccountName:         The AWS account name that contains the IAM user.
    IAMUserName:            The name of the IAM user.
    IAMUserPath:            The path of the IAM user.      
    IAMKeys:                API keys for the IAM user.
    ConsoleAccess:          If configured, the date that console access was provisioned for the IAM user.
    MemberofGroups:         The IAM groups that the IAM user is a member of.
.NOTES
    NAME......:  Get-AWSIAMUsers
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    Get-AWSIAMUsers
    Returns an array of PS Objects containing information about all IAM users in a given AWS account.
#>
function Get-AWSIAMUsers
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    )
    
    $IAMUsers = Get-IAMUsers
    $AllIAMUsers = @()

    if ($IAMUsers)
    {
        foreach ($IAMUser in $IAMUsers)
        {
            write-verbose "Retrieving information for IAMUser: $($IAMUser.UserName)"
            # Define empty array for IAM Users group memberships
            $IAMUserGroups = @()
            $IAMUserKeys = @()

            # Find any groups that the IAMuser is a member of
            $MemberofGroups = Get-IAMGroupForUser $($IAMUser.UserName) -ProfileName $ProfileName

            if ($MemberofGroups)
            {
                foreach ($MemberofGroup in $MemberofGroups)
                {
                    write-verbose "IAMUser is member of IAM Group: $($MemberofGroup.GroupName)"
                    $MemberofGroupName = $($MemberofGroup.GroupName) + ","
                    $IAMUserGroups += $MemberofGroupName
                } 
            }

            else 
            {
                $IAMUserGroups = "NONE"
            }
            write-verbose "IAMUser group memberships: $IAMUserGroups"

            # Return information about whether user has console access, if no profile is found set variable to "NO"
            Try 
            {
               $ConsoleAccessDate = Get-IAMLoginProfile $($IAMUser.UserName) -ProfileName $ProfileName | select -expand CreateDate
               $ConsoleAccess = "YES, Created: $ConsoleAccessDate"
               write-verbose "IAMUser has console access."
            }

            Catch
            {
               $ConsoleAccess = 'NONE' 
               write-verbose "IAMUser has no console access."
            }

            # Return information about whether user has API access keys, if no keys are found set variable to "NO"
            Try 
            {
               $UserKeys = Get-IAMAccessKey $($IAMUser.UserName) -ProfileName $ProfileName

               foreach ($UserKey in $UserKeys)
               {
                    $KeyInfo = "$($UserKey.Status) : $($UserKey.AccessKeyId)" + " |"
                    $IAMUserKeys += $KeyInfo
               }
            }

            Catch
            {
               $IAMUserKeys = 'NONE' 
            }
            
            write-verbose "IAMUser key: $IAMUserKeys ."

            # Return AWS account number from account
            $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
            $AccountNumber = $Matches[0]

            # Create object, populate information return from function
            $IAMUserInfo = [ordered] @{
                            AWSAccountNumber="$AccountNumber";
                            AWSAccountName="$ProfileName"; 
                            IAMUserName="$($IAMUser.username)";
                            IAMUserPath="$($IAMUser.path)";
                            IAMKeys="$IAMUserKeys";
                            ConsoleAccess="$ConsoleAccess";
                            MemberofGroups="$IAMUserGroups"
                        }


            $IAMUserInfoObj = New-Object -Type PSObject -Prop $IAMUserInfo
            $AllIAMUsers += $IAMUserInfoObj
        }
        $AllIAMUsers
    }

    else 
    {
        write-verbose "No IAM Users found in account."     
    } 
}
<#
.SYNOPSIS
    Gets IAM Group information.
.DESCRIPTION
    Returns information for IAM groups in a given AWS account. IAM is not a region specific service, so information is for the AWS account.
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns $AllIAMGroups which is an array of PS objects containing the following information:
    AWSAccountNumber:       The AWS account number that contains the IAM user.
    AWSAccountName:         The AWS account name that contains the IAM user.
    IAMGroupName:           The name of the IAM group.
    IAMGroupPath:           The path of the IAM group.      
    IAMGroupPolicies:       Policies attached to the IAM group.
    MembersofIAMGroup:      The IAM users that are members of the IAM group.
.NOTES
    NAME......:  Get-AWSIAMGroups
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    Get-AWSIAMGroups
    Returns an array of PS Objects containing information about all IAM users in a given AWS account.
#>
function Get-AWSIAMGroups
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    )

    $IAMGroups = Get-IAMGroups
    $AllIAMGroups = @()

    if ($IAMGroups)
    {
        foreach ($IAMGroup in $IAMGroups)
        {
            write-verbose "Retrieving information for IAMGroup: $($IAMGroup.GroupName)"
            
            $IAMGroupMembers = @()
            $MembersofIAMGroup = ((get-iamgroup $($IAMGroup.GroupName) -ProfileName $ProfileName).users | select -expand Username)

            if ($MembersofIAMGroup)
            {
                foreach ($MemberofIAMGroup in $MembersofIAMGroup)
                {
                    write-verbose "IAMGroup contains IAM User: $MemberofIAMGroup"
                    $IAMGroupMembers += $MemberofIAMGroup
                }
            }

            else 
            {
                $IAMGroupMembers = 'EMPTY'
                write-verbose "IAMGroup is: $IAMGroupMembers"
            }

            $GroupPolicies = Get-IAMGroupPolicies $($IAMGroup.GroupName)

            if (!($GroupPolicies))
            {
                write-verbose "IAMGroup does not have any policy attached"
                $GroupPolicies = 'NONE'
            }

            # Return AWS account number from account
            $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
            $AccountNumber = $Matches[0]

            # Create object, populate information return from function
            $IAMGroupInfo = [ordered] @{
                                AWSAccountNumber="$AccountNumber";
                                AWSAccountName="$ProfileName";
                                IAMGroupName="$($IAMGroup.GroupName)";
                                IAMGroupPath="$($IAMGroup.Path)";
                                GroupPolicies="$GroupPolicies";
                                MembersofGroup="$IAMGroupMembers"
                            }


            $IAMGroupObj = New-Object -Type PSObject -Prop $IAMGroupInfo
            $AllIAMGroups += $IAMGroupObj
        }

        $AllIAMGroups
    }

    else 
    {
        write-verbose "No IAM Groups found in account."     
    } 
}
<#
.SYNOPSIS
    Gets EC2 instance information.
.DESCRIPTION
    Returns information about EC2 instances in a given AWS region.
.PARAMETER Region
    The AWS region to check for EC2 instances in. 
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns $AllEC2Instances which is a PS object containing the following information:
    AWSAccountNumber:       The AWS account number that contains the EC2 instance.
    AWSAccountName:         The AWS account name that contains the EC2 instance.
    AWSRegion:              The AWS region containing the EC2 instance.
    InstanceID:             The instance ID of the EC2 instance. 
    InstanceType:           The type of the EC2 instance.
    NameTag:                The name tag of the EC2 instance (if configured).
    KeyName:                The name keypair used to launch the EC2 instance.
    PrivateIP:              The private IP address of the EC2 instance.
    PublicIP:               The public IP address of the EC2 instance.
    VPCID:                  The VPCID of the EC2 instance (if in a VPC).
    State:                  The state of the EC2 instance. 
    LaunchTime:             The date when the EC2 instance was first launched.
.NOTES
    NAME......:  Get-AWSEC2Instances
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    Get-EC2Instances -Region 'us-east-1'
#>
function Get-AWSEC2Instances
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true,HelpMessage="The system name of the AWS region in which the operation should be invoked. For example: us-east-1")]
        [ValidateSet("us-east-1","us-west-1","us-west-2","eu-west-1","eu-central-1","ap-northeast-1","ap-southeast-1","ap-southeast-2","sa-east-1")] 
        [String]
        $Region,

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    ) 

    $EC2Instances = (get-ec2instance -region $Region -ProfileName $ProfileName).instances       
    $AllEC2Instances = @()

    if ($EC2Instances)
    {
        write-verbose "Found Instances in Region: $Region"  
        
        foreach ($Instance in $EC2Instances)
        {
            Try
            {
                $NameTag = $Instance | select -expand tags | Where-Object {$_.Key -like "Name"} | select -ExpandProperty Value         
            }

            Catch
            {
               $NameTag = 'NONE' 
            }

            write-verbose "Instance name tag: $NameTag "

            $PrivateIP = $($Instance.privateipaddress)
            
            if (!($PrivateIP))
            {
                $PrivateIP = 'NONE'
            }

            write-verbose "PrivateIP: $PrivateIP"

            $PublicIP = $($Instance.publicipaddress)
            
            if (!($PublicIP))
            {
                $PublicIP = 'NONE'
            }

            write-verbose "PublicIP: $PublicIP"

            $VPCID="$($Instance.VpcId)"
            
            if (!($VPCID))
            {
                $VPCID = 'NONE'
            }

            write-verbose "VPCID: $VPCID"

            # Return AWS account number from account
            $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
            $AccountNumber = $Matches[0]

            # Create object, populate information return from function              
            $EC2InstanceInfo = [ordered] @{
                                AWSAccountNumber="$AccountNumber";
                                AWSAccountName="$ProfileName";
                                AWSRegion="$region";
                                InstanceID="$($Instance.instanceID)";
                                InstanceType="$($Instance.instancetype)";
                                NameTag="$NameTag"
                                KeyName="$($Instance.keyname)";
                                PrivateIP="$PrivateIP";
                                PublicIP="$PublicIP ";
                                VPCID="$VPCID";
                                State="$($Instance.state.name.value)";
                                LaunchTime="$($Instance.launchtime)"
                            }

            $EC2InstanceObj = New-Object -Type PSObject -Prop $EC2InstanceInfo
            $AllEC2Instances += $EC2InstanceObj
        }

        $AllEC2Instances
    }

    else 
    {
        write-verbose "No EC2 Instances found in region: $region." 
    } 
}
<#
.SYNOPSIS
    Gets ELB information.
.DESCRIPTION
    Returns information about ELB's running in a given AWS region.
.PARAMETER Region
    The AWS region to check for ELB instances in.
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.     
.OUTPUTS
    Returns $DeletedUserObj which is a PS object containing the following information:
    AWSAccountNumber:       The AWS account number that contains the ELB.
    AWSAccountName:         The AWS account name that contains the ELB.
    AWSRegion:              The AWS region containing the ELB.
    ELBName:                The name of the ELB. 
    ELBDNSName:             The FQDN of the ELB.
    ELBPolicy:              The policy attached to the ELB.
    ELBCertificate:         The certificate installed on the ELB.
    ELBInstances:           List of any instances in the ELB.
    VPCID:                  The VPCID of the EC2 instance (if in a VPC).
    AZ:                     The availability zones that the ELB is associated with. 
    Use:                    The use of the ELB (internet-facing or internal)
    CreatedDate:            The date when the ELB was created.    
.NOTES
    NAME......:  Get-AWSELBs
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    Get-AWSELBs -Region 'us-east-1' -ProfileName 'MyProductionAccount'
#>
function Get-AWSELBs
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true,HelpMessage="The system name of the AWS region in which the operation should be invoked. For example: us-east-1")]
        [ValidateSet("us-east-1","us-west-1","us-west-2","eu-west-1","eu-central-1","ap-northeast-1","ap-southeast-1","ap-southeast-2","sa-east-1")] 
        [String]
        $Region,

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    ) 
    
    $ELBs = Get-ELBLoadBalancer -region $Region -ProfileName $ProfileName
    $AllELBs = @()

    if ($ELBs)
    {
        write-verbose "Found ELBs in Region: $Region"
        
        foreach ($ELB in $ELBs)
        {  
            write-verbose "Found ELB name: $($ELB.Loadbalancername)"
            $ELBCertificates = @()
            $ELBInstances = ""

            $ELBListeners = $(($ELB.listenerdescriptions).listener)

            foreach ($ELBListener in $ELBListeners)
            {
                $ELBCertificate =  $($ELBListener.SSLCertificateId)
                $ELBCertificates += $ELBCertificate
            }

            if (!($ELBCertificates))
            {
                $ELBCertificates = 'NONE'
            }

            write-verbose "ELB certificate: $ELBCertificates"

            $ELBPolicy = $(($ELB.Policies).otherpolicies)
            
            if (!($ELBPolicy))
            {
               $ELBPolicy = 'NONE' 
            }

            write-verbose "ELB policy: $ELBPolicy"

            $ELBInstances = $(($ELB.instances).instanceid) -join","
            
            if (!($ELBInstances))
            {
               $ELBInstances = 'NONE' 
            } 

            $VPCID="$($ELB.VPCID)"
            
            if (!($VPCID))
            {
                $VPCID = 'NONE'
            }			

            if ($($ELB.Scheme) -eq 'internet-facing')
            {
                $ExternalIPAddress = [System.Net.Dns]::GetHostEntry($($ELB.DNSName)).AddressList[0].IPAddressToString
            }

            else 
            {
                $ExternalIPAddress = 'N/A'    
            }
            
            # Return AWS account number from account
            $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
            $AccountNumber = $Matches[0]

            # Create object, populate information return from function  
            $ELBInfo = [ordered] @{
                    AWSAccountNumber="$AccountNumber";
                    AWSAccountName="$ProfileName";
                    AWSRegion="$region";             
                    ELBName="$($ELB.Loadbalancername)";
                    ELBDNSName="$($ELB.DNSName)";
                    ELBPolicy="$ELBPolicy";
                    ELBCertificate="$ELBCertificates";
                    ELBInstances="$ELBInstances";
                    ExternalIP="$ExternalIPAddress"
                    VPCID="$VPCID";
                    AZ="$($($ELB.AvailabilityZones) -join",")";
                    Use="$($ELB.Scheme)";
                    CreatedDate= "$($ELB.CreatedTime)"; 
                } 
                
            $ELBobj = New-Object -Type PSObject -Prop $ELBInfo
            $AllELBs += $ELBobj
        }
        $AllELBs
    }

    else 
    {
        write-verbose "No ELBs found in region: $region."     
    }
} 
<#
.SYNOPSIS
    Gets Subnet information.
.DESCRIPTION
    Returns information about subnets in a given AWS region.
.PARAMETER Region
    The AWS region to check for subnets in. 
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns $SubnetObj which is a PS object containing the following information:
    AWSAccountNumber:       The AWS account number that contains the ELB.
    AWSAccountName:         The AWS account name that contains the ELB.
    AWSRegion:              The AWS region containing the ELB.
    SubnetID:               The ID of the subnet.
    VPCID:                  The VPCID of the EC2 instance (if in a VPC).
    CIDR:                   The CIDR block associated with the subnet.
    AZ:                     The name of the availability zone that the subnet is associated with.
    NameTag:                The name tag of the subnet (if configured).
    InstanceIPs:            The instance IPs associated with the subnet.
.NOTES
    NAME......:  Get-AWSSubnets
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    Get-AWSSubnets -Region 'us-east-1'
#>
function Get-AWSSubnets
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true,HelpMessage="The system name of the AWS region in which the operation should be invoked. For example: us-east-1")]
        [ValidateSet("us-east-1","us-west-1","us-west-2","eu-west-1","eu-central-1","ap-northeast-1","ap-southeast-1","ap-southeast-2","sa-east-1")] 
        [String]
        $Region,

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    ) 

    $Subnets = Get-EC2Subnet -Region $Region -ProfileName $ProfileName
    $Instances = (Get-EC2Instance -Region $Region -ProfileName $ProfileName).instances 
    $AllSubnets = @()

    if ($Subnets)
    {
        write-verbose "Found $($Subnets.count) Subnets in Region: $Region"
    
        foreach ($Subnet in $Subnets)
        {  
            write-verbose "Found Subnet with ID: $($Subnet.SubnetId)"
            $InstancesIDsinSubnet = @()
            $Nametag = ""

			Try
            {
                $NameTag = $Subnet | select -expand tags | Where-Object {$_.Key -like "Name"} | select -ExpandProperty Value         
            }

            Catch
            {
               $NameTag = 'NONE' 
            }

            write-verbose "Instance name tag: $NameTag "

            foreach ($Instance in $Instances)
            {  
                Try
                {
                    $InstancesubnetID = $Instance | select -expand SubnetID

                    if ($InstancesubnetID -eq $($Subnet.SubnetId) )
                    {
                        $InstancesIDsinSubnet += $($Instance.InstanceID) #+ "," 
                    }
                }

                Catch
                {
                    $Host.UI.WriteErrorLine("`nUnable to retrieve subnets.`n$_.error`n")
                }
            } 

            if (!($InstancesIDsinSubnet))
            {
                $InstancesIDsinSubnet = 'NONE'
            }

            $InstancesIDsinSubnet = ($InstancesIDsinSubnet -Join ",")

            write-verbose "Subnet contains the following instances: $InstancesIDsinSubnet"
            
            # Return AWS account number from account
            $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
            $AccountNumber = $Matches[0]

            # Create object, populate information return from function  
            $SubnetInfo = [ordered] @{
                            AWSAccountNumber="$AccountNumber";
                            AWSAccountName="$ProfileName";
                            AWSRegion="$Region";    
                            VPCID="$($Subnet.VPCID)";
                            SubnetID = "$($Subnet.SubnetId)";
                            CIDR ="$($Subnet.CidrBlock)"; 
                            AZ = "$($Subnet.AvailabilityZone)"; 
                            NameTag ="$nametag" ;
                            InstanceIDs = "$InstancesIDsinSubnet" 
                        }

            $SubnetObj = New-Object -Type PSObject -Prop $SubnetInfo                            
            $AllSubnets += $SubnetObj
        }

        $AllSubnets 
    }

    else 
    {
        write-verbose "No Subnets found in region: $region."     
    }
}
<#
.SYNOPSIS
    Gets IAM Password Policy information.
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.DESCRIPTION
    Returns information for IAM password policy in a given AWS account. IAM is not a region specific service, so information is for the AWS account.
.OUTPUTS
    Returns $PasswordPolicy which is an array of PS objects containing the following information:
    AWSAccountNumber:               The AWS account number whos password policy is being aduited.
    AWSAccountName:                 The AWS account name that contains the ELB.
    AllowUserstoChangePassword:     Allows use the IAM console to change their own passwords.
    MinPasswordLength:              The minimum number of characters allowed in an IAM user password (6 to 128 
                                    characters)
    MaxPasswordAge:                 Sets password expiration, user must reset password before logging into the
                                    console (1 to 1095 days)               
    RequireUpperCase:               The password must contain at least one uppercase character from the basic Latin
                                    alphabet (A to Z).
    RequireLowerCase:               The password must contain at least one lowercase character from the basic Latin
                                    alphabet (a to z).
    RequireNumbers:                 The password must contain at least one numeric character (0 to 9).
    RequireSpecialCharacters:       The password contain at least one of the following non-alphanumeric characters: 
                                    (! @ # $ % ^ & * ( ) _ + - = [ ] { } | ') .
    PasswordHistory:                Prevents users from reusing a specified number of previous passwords (1 to 24)
.NOTES
    NAME......:  Get-AWSIAMPasswordPolicy
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    Get-AWSIAMPasswordPolicy
    Returns an array of PS Objects containing information about IAM password policy in a given AWS account.
#>
function Get-AWSIAMPasswordPolicy
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    ) 
	
	Try
	{
		$PWDPolicy = Get-IAMAccountPasswordPolicy
		$AllowUserstoChangePassword="$($PWDPolicy.AllowUsersToChangePassword)";
		$MinPasswordLength="$($PWDPolicy.MinimumPasswordLength)"; 
		$MaxPasswordAge="$($PWDPolicy.MaxPasswordAge)";   
		$RequireUpperCase="$($PWDPolicy.RequireUppercaseCharacters)";
		$RequireLowerCase="$($PWDPolicy.RequireLowercaseCharacters)";
		$RequireNumbers="$($PWDPolicy.RequireNumbers)";
		$RequireSpecialCharecters ="$($PWDPolicy.RequireSymbols)";
		$PasswordHistory = "$($PWDPolicy.PasswordReusePrevention)";
		$AdminResetAfterExpired="$($PWDPolicy.HardExpiry)"
	}
	
	Catch
	{
		Return $Null
		$AllowUserstoChangePassword="NOT CONFIGURED";
		$MinPasswordLength="NOT CONFIGURED"; 
		$MaxPasswordAge="NOT CONFIGURED";   
		$RequireUpperCase="NOT CONFIGURED";
		$RequireLowerCase="NOT CONFIGURED";
		$RequireNumbers="NOT CONFIGURED";
		$RequireSpecialCharecters ="NOT CONFIGURED";
		$PasswordHistory = "NOT CONFIGURED";
		$AdminResetAfterExpired="NOT CONFIGURED"
	}
	
    # Return AWS account number from account
    $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
    $AccountNumber = $Matches[0]

    # Create object, populate information return from function 
    $IAMPasswordPolicy = [ordered] @{
                            AWSAccountNumber="$AccountNumber";
                            AWSAccountName="$ProfileName";
                            AllowUserstoChangePassword="$AllowUserstoChangePassword";
                            MinPasswordLength="$MinPasswordLength"; 
                            MaxPasswordAge="$MaxPasswordAge";   
                            RequireUpperCase="$RequireUpperCase";
                            RequireLowerCase="$RequireLowerCase";
                            RequireNumbers="$RequireNumbers";
                            RequireSpecialCharecters ="$RequireSpecialCharecters";
                            PasswordHistory = "$PasswordHistory";
                            AdminResetAfterExpired="$AdminResetAfterExpired"
                        }

    $PasswordPolicy = New-Object -Type PSObject -Prop $IAMPasswordPolicy 
    $PasswordPolicy
} 
<#
.SYNOPSIS
    Sets IAM Password Policy.
.DESCRIPTION
    Sets IAM password policy in a given AWS account. IAM is not a region specific service, so information is for the AWS account as a whole.
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns $NewPasswordPolicy which is an array of PS objects containing the following information:
    AWSAccountNumber:               The AWS account number whos password policy is being aduited.
    AWSAccountName:                 The AWS account name that contains the ELB.
    AllowUserstoChangePassword:     Allows use the IAM console to change their own passwords (default value is true)
    MinPasswordLength:              The minimum number of characters allowed in an IAM user password (6 to 128 
                                    characters - default value is 12)            
    RequireUpperCase:               The password must contain at least one uppercase character from the basic Latin
                                    alphabet (A to Z - default value is true)
    RequireLowerCase:               The password must contain at least one lowercase character from the basic Latin
                                    alphabet (a to z - default value is true)
    RequireNumbers:                 The password must contain at least one numeric character (0 to 9 - default value 
                                    is true)
    RequireSpecialCharacters:       The password contain at least one of the following non-alphanumeric characters: 
                                    (! @ # $ % ^ & * ( ) _ + - = [ ] { } | ' - default value is true)
    MaxPasswordAge:                 Sets password expiration, user must reset password before logging into the
                                    console (1 to 1095 days - default value is 0, so expiration is not enabled)   
    PasswordHistory:                Prevents users from reusing a specified number of previous passwords (1 to 24 - 
                                    default value is 24)
    AdminResetAfterExpired:         Require admnistrator to reset users password after expiration. (True or False -
                                    default value is false)
.NOTES
    NAME......:  Set-AWSIAMPasswordPolicy
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    Set-AWSIAMPasswordPolicy
    Returns an array of PS Objects containing information about IAM password policy in a given AWS account.
#>
function Set-AWSIAMPasswordPolicy
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false,HelpMessage="Define whether users can use the IAM console to change their own passwords (default value is true).")]
        [ValidateNotNullOrEmpty()]
        [string]
        $AllowUsersToChangePassword = $True,

        [Parameter(Mandatory=$false,HelpMessage="Enter minimum number of characters allowed in an IAM user password (6 to 128 characters - default value is 12).")]
        [ValidateNotNullOrEmpty()]
        [int]
        $MinPasswordLength = 12,

        [Parameter(Mandatory=$false,HelpMessage="Define whether the password must contain at least one uppercase character from the basic Latin alphabet (A to Z - default value is true)")]
        [ValidateNotNullOrEmpty()]
        [bool]
        $RequireUpperCase = $True,

        [Parameter(Mandatory=$false,HelpMessage="Define whether the password must contain at least one lowercase character from the basic Latin alphabet (a to z - default value is true)")]
        [ValidateNotNullOrEmpty()]
        [bool]
        $RequireLowerCase = $True,

        [Parameter(Mandatory=$false,HelpMessage="Define whether the password must contain at least one numeric character (0 to 9 - default value is true)")]
        [ValidateNotNullOrEmpty()]
        [bool]
        $RequireNumbers = $True,

        [Parameter(Mandatory=$false,HelpMessage="Define whether the password must contain at least one of the following non-alphanumeric characters (! @ # $ % ^ & * ( ) _ + - = [ ] { } | ' - default value is true)")]
        [ValidateNotNullOrEmpty()]
        [bool]
        $RequireSpecialCharacters = $True,

        [Parameter(Mandatory=$false,HelpMessage="Define whether there is a maxium password age, which enables password expiration (1 to 1095 days - default value is 0, so expiration is not enabled)")]
        [ValidateNotNullOrEmpty()]
        [int]
        $MaxPasswordAge = 90,        

        [Parameter(Mandatory=$false,HelpMessage="Prevent users from reusing a specified number of previous passwords (1 to 24 - default value is 24)")]
        [ValidateNotNullOrEmpty()]
        [int]
        $PasswordHistory = 24,

        [Parameter(Mandatory=$false,HelpMessage="Require admnistrator to reset users password after expiration. (True or False - default value is false)")]
        [ValidateNotNullOrEmpty()]
        [bool]
        $AdminResetAfterExpired = $False
    )
    
    # Set allow users to change password
    if (((Get-IAMAccountPasswordPolicy -ProfileName $ProfileName).AllowUsersToChangePassword) -ne $AllowUsersToChangePassword)
    {
        $UpdatedAllowUsersToChangePassword = "Updated, new setting: $AllowUsersToChangePassword"
    }

    else 
    {
        $UpdatedAllowUsersToChangePassword = "$AllowUsersToChangePassword"
    }
    write-verbose "Allow Users to Change Password: $UpdatedAllowUsersToChangePassword"

    # Set require admnistrator to reset users password after expiration 
    if (((Get-IAMAccountPasswordPolicy -ProfileName $ProfileName).HardExpiry) -ne $AdminResetAfterExpired)
    {
        $UpdatedAllowUsersToChangePassword = "Updated, new setting: $AdminResetAfterExpired"
    }
    else 
    {
        $UpdatedAdminResetAfterExpired = "$AdminResetAfterExpired"
    }
    write-verbose "Password history to prevent reuse: $UpdatedAdminResetAfterExpired"

    # Set minimum password length
    if (((Get-IAMAccountPasswordPolicy -ProfileName $ProfileName).MinimumPasswordLength) -ne $MinPasswordLength)
    {
        $UpdatedMinPasswordLength = "Updated, now set to: $MinPasswordLength"
    }

    else 
    {
        $UpdatedMinPasswordLength = "$MinPasswordLength"
    }
    write-verbose "Minimum Password Length: $UpdatedMinPasswordLength"

    # Set require uppercase characters
    if (((Get-IAMAccountPasswordPolicy -ProfileName $ProfileName).RequireUppercaseCharacters) -ne $RequireUpperCase)
    {
        $UpdatedRequireUpperCase = "Updated, now set to: $RequireUpperCase"
    }

    else 
    {
        $UpdatedRequireUpperCase = "$RequireUpperCase"
    }
    write-verbose "Require uppercase characters: $UpdatedRequireUpperCase"


    # Set require lowercase characters
    if (((Get-IAMAccountPasswordPolicy -ProfileName $ProfileName).RequireLowercaseCharacters) -ne $RequireLowerCase)
    {
        $UpdatedRequireLowerCase = "Updated, now set to: $RequireLowerCase"
    }

    else 
    {
        $UpdatedRequireLowerCase = "$RequireLowerCase"
    }
    write-verbose "Require lowercase characters: $UpdatedRequireLowerCase"

    # Set require numbers
    if (((Get-IAMAccountPasswordPolicy -ProfileName $ProfileName).RequireNumbers) -ne $RequireNumbers)
    {
        $UpdatedRequireNumbers = "Updated, now set to: $RequireNumbers"
    }

    else 
    {
        $UpdatedRequireNumbers = "$RequireNumbers"
    }
    write-verbose "Require numbers: $UpdatedRequireNumbers"

    # Set require special characters
    if (((Get-IAMAccountPasswordPolicy -ProfileName $ProfileName).RequireSymbols) -ne $RequireSpecialCharacters)
    {
        $UpdatedRequireSpecialCharacters = "Updated, now set to: $RequireSpecialCharacters"
    }

    else 
    {
        $UpdatedRequireSpecialCharacters = "$RequireSpecialCharacters"
    }
    write-verbose "Require special characters: $UpdatedRequireSpecialCharacters"

    # Set max password age
    if (((Get-IAMAccountPasswordPolicy -ProfileName $ProfileName).MaxPasswordAge) -ne $MaxPasswordAge)
    {
        $UpdatedMaxPasswordAge = "Has been updated. Setting: $MaxPasswordAge"
    }

    else 
    {
        $UpdatedMaxPasswordAge = "$MaxPasswordAge"
    }
    write-verbose "Max password age: $UpdatedMaxPasswordAge"

    # Set password history to prevent reuse
    if (((Get-IAMAccountPasswordPolicy -ProfileName $ProfileName).PasswordReusePrevention) -ne $PasswordHistory)
    {
        $UpdatedPasswordHistory = "Has been updated. Setting: $PasswordHistory"
    }

    else 
    {
        $UpdatedPasswordHistory = "$PasswordHistory"
    }
    write-verbose "Password history to prevent reuse: $UpdatedPasswordHistory"

    Update-IAMAccountPasswordPolicy `
        -AllowUsersToChangePassword $AllowUsersToChangePassword `
        -HardExpiry $AdminResetAfterExpired `
        -MaxPasswordAge $MaxPasswordAge `
        -MinimumPasswordLength $MinPasswordLength `
        -PasswordReusePrevention $PasswordHistory `
        -RequireLowercaseCharacters $RequireLowercaseCharacters `
        -RequireNumbers $RequireNumbers `
        -RequireSymbols $RequireSymbols `
        -RequireUppercaseCharacters $RequireUppercaseCharacters `
        -ProfileName $ProfileName `

    # Return AWS account number
    $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
    $AccountNumber = $Matches[0] 

    $IAMPasswordPolicy = [ordered] @{
                            AWSAccountNumber="$AccountNumber";
                            AWSAccountName="$ProfileName";
                            AllowUserstoChangePassword="$UpdatedAllowUsersToChangePassword";
                            MinPasswordLength="$UpdatedMinPasswordLength"; 
                            MaxPasswordAge="$UpdatedMaxPasswordAge";   
                            RequireUpperCase="$UpdatedRequireUpperCase";
                            RequireLowerCase="$UpdatedRequireLowerCase";
                            RequireNumbers="$UpdatedRequireNumbers";
                            RequireSpecialCharecters ="$UpdatedRequireSpecialCharacters";
                            PasswordHistory = "$UpdatedPasswordHistory";
                            AdminResetAfterExpired="$UpdatedAdminResetAfterExpired"
                        }

    $PasswordPolicy = New-Object -Type PSObject -Prop $IAMPasswordPolicy 
    $PasswordPolicy
}  
<#
.SYNOPSIS
    Searches for instance in AWS account.
.DESCRIPTION
    Searches all regions in an AWS account for EC2 instances based on input of public IP address, private IP address or instance ID. This is very useful when searching for instances identified in AWS Abuse Report notifications since the account information is not included in the report.
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    If found returns $FoundInstanceObj which is a PS object containing the following information:
    AWSAccountNumber:       The AWS account number that contains the ELB.
    AWSAccountName:         The AWS account name that contains the ELB.
    AWSRegion:              The AWS region containing the ELB.
    InstanceID:             The instance ID of the EC2 instance.
    PrivateIP:              The private IP address of the EC2 instance.
    PublicIP:               The public IP address of the EC2 instance.
    SecurityGroupName:      The name of the security group for the EC2 instance.
    Platform:               The OS that the EC2 instance is running (Window or Linux).
    KeyName:                The name of the key pair used when the EC2 instance was launched.
.NOTES
    NAME......:  Find-EC2Instance
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    Find-EC2Instance
    Returns an array of PS Objects containing information about all IAM users in a given AWS account.
#>
function Find-AWSEC2Instance
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true,HelpMessage="The system name of the AWS region in which the operation should be invoked. For example: us-east-1")]
        [ValidateSet("us-east-1","us-west-1","us-west-2","eu-west-1","eu-central-1","ap-northeast-1","ap-southeast-1","ap-southeast-2","sa-east-1")] 
        [String]
        $Region,

        [Parameter(Mandatory=$false,HelpMessage="Enter the IP address (public or private) of the instance you are searching for.")]
        [String]
        $InstanceIP,

        [Parameter(Mandatory=$false,HelpMessage="Enter the instance ID'sof the instance you are searching for.")]
        [String]
        $InstanceID,

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    ) 

    

    if ($InstanceIP)
    {
        write-verbose "Searching account for instance with IP: $InstanceIP"
    }

    else 
    {
        write-verbose "Searching account for instance with instance ID: $InstanceID"        
    }
    $Instances = (get-ec2instance -region $Region -ProfileName $ProfileName).instances 

    
    write-verbose "Searching: $($Instances.count) instances in region: $Region"
    
    foreach ($Instance in $Instances)
    {        
        $FoundInstance = $Instance | Where { ($_.PrivateIpAddress -eq $InstanceIP) -or ($_.PublicIpAddress -eq $InstanceIP) -or ($_.InstanceID -eq $InstanceID) } 
     
        if ($FoundInstance)
        {
            write-verbose "Instance found"

            $InstancePlatform = $($Instance.platform)
            if (!($InstancePlatform))
            {
                $InstancePlatform = 'Linux'
            }
            # Return AWS account number from account
            $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
            $AccountNumber = $Matches[0]

            # Create object, populate information return from function 
            $FoundInstanceInfo = [ordered] @{
                                    AWSAccountNumber="$AccountNumber";
                                    AWSAccountName="$ProfileName";
                                    AWSRegion="$Region";  
                                    InstanceID="$($Instance.InstanceID)";
                                    InternalIP="$($Instance.PrivateIpAddress)";   
                                    ExternalIP="$($Instance.PublicIpAddress)";
                                    SecurityGroupName="$($Instance.SecurityGroups.groupname)";
                                    Platform="$Instanceplatform";
                                    KeyName="$($Instance.KeyName)"
                                }

            $FoundInstanceObj = New-Object -Type PSObject -Prop $FoundInstanceInfo    
            Return $FoundInstanceObj
            
        }
    }

    write-verbose "Instance not found in region"     
}
<#
.SYNOPSIS
    Runs Trusted Advisor check against AWS and returns security related checks.
.DESCRIPTION
    Runs Trusted Advisor checks and filters results to include security specific checks (including some utiliztion checks to enable termination of under-utilized resources). Checks include
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns $TACheckObj which is an array of PS objects containing the following information:
    AWSAccountNumber:               The AWS account number whos password policy is being aduited.
    AWSAccountName:                 The AWS account name that contains the ELB.
    MFAEnabledforRoot:              Checks whether MFA is enabled on the root AWS credential.
    OpenSecurityGroups:             Checks for security groups that allow unrestricted access (source = 0.0.0.0/0) on 
                                    specific ports.
    OpenS3Permissions:              Checks for S3 buckets that allow unrestricted access.
    OpenRDSGroupRules:              Checks for RDS Security groups that allow unrestricted access (source = 0.0.0.0/0)
    Route53:                        Checks for an SPF resource record set for each MX resource (helps reduce spam).
    Cloudtrail:                     Checks whether cloudtrail is enabled for the account.
    LowUseInstances                 Checks for instances where CPU utilization was 10% or less and network I/O was 
                                    5 MB or less on 4 or more days.
    LowUseELBs:                     Checks for load balancers that are not actively used.
.NOTES
    NAME......:  Invoke-TrustedAdvisorChecks
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    Invoke-TrustedAdvisorChecks
    Returns a PS Object containing information about Trusted Advisor checks related to security and resource usage.
#>
function Invoke-TrustedAdvisorChecks
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    )

    Try
    {
        $TAChecks = Get-ASATrustedAdvisorChecks -language en -ProfileName $ProfileName | where { $_.category -eq 'security' -or $_.category -eq'cost_optimizing'}

        foreach ($TACheck in $TAChecks)
        {
            # Return Trusted Advisor check information for individual check. Return resources checked and resourced flagged
            $TACheckStatus = Get-ASATrustedAdvisorCheckResult -CheckId $($TACheck.ID) -Language en -ProfileName $ProfileName | select -expand status
            $ResourcesChecked = (Get-ASATrustedAdvisorCheckResult -CheckId $($TACheck.ID) -Language en -ProfileName $ProfileName | select ResourcesSummary | select -expand Resourcessummary).ResourcesProcessed
            $Resourcesflagged = (Get-ASATrustedAdvisorCheckResult -CheckId $($TACheck.ID) -Language en -ProfileName $ProfileName | select ResourcesSummary | select -expand Resourcessummary).Resourcesflagged

            # Calculate percentage of resources flagged if not equal to 0 resources        
            if ($ResourcesChecked -ne '0')
            {
                $Percentageflagged = $("{0:N2}" -f (($Resourcesflagged/$ResourcesChecked)*100) ) + "%"
            } 

            # Define 'Status' to return consistent value of Review Configuration if error or warning are returned
            if ($TACheckStatus -ne 'ok')
            {
                $TACheckStatus = "REVIEW CONFIGURATION: "#STATUS: $TACheckStatus"
            }

            # Define 'Status' of OK if ok
            else
            {
                $TACheckStatus = 'OK'
            }

            # Define and populate variable for check: Security Groups - Specific Ports Unrestricted
            if ($($TACheck.ID) -eq 'HCP4007jGY' )
            {
                write-verbose "TA Category: $($TACheck.Category) CheckName: $($TACheck.Name) CheckID: ($($TACheck.ID)) "        
                $OpenSecurityGroups = "$Resourcesflagged of $ResourcesChecked ($Percentageflagged) of rules flagged as Open to 0.0.0.0/0"
                write-verbose "Open SecurityGroups: $OpenSecurityGroups"  
            }

            # Define and populate variable for check: Amazon S3 Bucket Permissions    
            elseif ($($TACheck.ID) -eq 'Pfx0RwqBli' )
            {
                write-verbose "TA Category: $($TACheck.Category) CheckName: $($TACheck.Name) CheckID: ($($TACheck.ID)) " 
                $S3Permissions = "$Resourcesflagged of $ResourcesChecked ($Percentageflagged) of buckets flagged as Open."
                write-verbose "S3 Bucket Permissions: $S3Permissions"   
            }

            # Define and populate variable for check: Amazon RDS Security Group Access Risk
            if ($($TACheck.ID) -eq 'nNauJisYIT' )
            {
                write-verbose "TA Category: $($TACheck.Category) CheckName: $($TACheck.Name) CheckID: ($($TACheck.ID)) " 

                if ($ResourcesChecked -eq '0')
                {
                    $RDSGroups = "OK - No RDS Groups Configured"
                }

                else 
                {
                    $RDSGroups = "$Resourcesflagged of $ResourcesChecked ($Percentageflagged) RDS rules flagged as Open."
                }

                write-verbose "RDS Groups: $RDSGroups"
            }

            # Define and populate variable for check: Amazon Route 53 MX and SPF Resource Record Sets
            if ($($TACheck.ID) -eq 'c9D319e7sG' )
            {
                write-verbose "TA Category: $($TACheck.Category) CheckName: $($TACheck.Name) CheckID: ($($TACheck.ID)) " 

                if ($ResourcesChecked -eq '0')
                {
                    $Route53 = "OK - No Route53 Records Configured"
                }

                else 
                {
                    $Route53 = "$Resourcesflagged of $ResourcesChecked ($Percentageflagged) of records flagged."
                }

                write-verbose "Route 53: $Route53"
            }

            # Define and populate variable for check: Low Utilization Amazon EC2 Instances
            if ($($TACheck.ID) -eq 'Qch7DwouX1' )
            {
                write-verbose "TA Category: $($TACheck.Category) CheckName: $($TACheck.Name) CheckID: ($($TACheck.ID))" 
                $LowUseInstances = "$Resourcesflagged of $ResourcesChecked ($Percentageflagged) of instances flagged as low Use"
                write-verbose "Low utilization Instances: $LowUseInstances"
                
            } 

            # Define and populate variable for check: Idle Load Balancers
            if ($($TACheck.ID) -eq 'hjLMh88uM8' )
            {
                write-verbose "TA Category: $($TACheck.Category) CheckName: $($TACheck.Name) CheckID: ($($TACheck.ID))"
                $LowUseELBs = "$Resourcesflagged of $ResourcesChecked ($Percentageflagged) of ELB's flagged as low use"
                write-verbose "Low utilization ELB's: $LowUseELBs"
                
            }                         

            # Define and populate variable for check: MFA on Root Account. Define status as review (not enabled)
            if ($($TACheck.ID) -eq '7DAFEmoDos' )
            {
                write-verbose "TA Category: $($TACheck.Category) CheckName: $($TACheck.Name) CheckID: ($($TACheck.ID))" 
                if ($TACheckStatus -eq 'REVIEW CONFIGURATION')
                {
                    $MFARoot = "REVIEW CONFIGURATION - MFA Not Enabled for Root"
                }

                else
                {
                    $MFARoot = "OK - MFA Enabled for Root"
                }

                write-verbose "MFA on Root: $MFARoot"
            }
        }

        $Cloudtrail = "REVIEW: Not Deployed"
    }

    Catch
    {
        $Host.UI.WriteErrorLine("`nUnable to retrieve Trusted Advisor Checks.`n$_.error`n")
        $MFARoot = "UNABLE TO RETRIEVE"                           
        $OpenSecurityGroups = "UNABLE TO RETRIEVE"  
        $OpenS3Permissions = "UNABLE TO RETRIEVE"  
        $OpenRDSGroupRules = "UNABLE TO RETRIEVE"  
        $Route53 = "UNABLE TO RETRIEVE"  
        $LowUseInstances = "UNABLE TO RETRIEVE"  
        $LowUseELBs = "UNABLE TO RETRIEVE"  
        $Cloudtrail = "UNABLE TO RETRIEVE"         
    }

    # Return AWS account number
    $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
    $AccountNumber = $Matches[0] 

    # Create custom object containing all information returned from account
    $TACheck = [ordered] @{
                    AWSAccountNumber="$AccountNumber";
                    AWSAccountName="$ProfileName";
                    MFARoot="$MFARoot"                            
                    OpenSecurityGroups="$OpenSecurityGroups";
                    OpenS3Permissions="$S3Permissions";
                    OpenRDSGroupRules="$RDSGroups";
                    Route53="$Route53";
                    LowUseInstances="$LowUseInstances";
                    LowUseELBs="$LowUseELBs"
                    Cloudtrail="$Cloudtrail"
                    }
    $TACheckObj = New-Object -Type PSObject -Prop $TACheck
    $TACheckObj
}
<#
.SYNOPSIS
    Finds IAM User account(s).
.DESCRIPTION
    Finds IAM user account(s) in the default AWS account.
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.PARAMETER UserName
    The name of the IAM user to find. 
.OUTPUTS
    Returns $FindIAMUsers which is an array of PS objects containing the following information:
    AWSAccountNumber:       The AWS account number that contains the IAM user.
    AWSAccountName:         The AWS account name that contains the IAM user.
    UserName:               The username of the IAM user the keys are being replaced for.
.NOTES
    NAME......:  Find-AWSIAMUser
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    Find-AWSIAMUsers -Usernames 'MYUSER' 
    Search for the IAM accounts MYUSER in the AWS account.
.EXAMPLE
    Find-AWSIAMUser -Usernames 'MYUSER,MYUSER1,MYUSER2' 
    Search for the IAM accounts MYUSER,MYUSER1,MYUSER2 in the AWS account.
#>
function Find-AWSIAMUser
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true,HelpMessage="Enter the names of the IAM users you want to find.")]
        [string[]] 
        $Usernames,

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    ) 

    # Empty array to add PS objects to
    $FindIAMUsers = @()

    # Split array of usernames and loop through each, trimming input to remove spaces.
    $Usernames = $Usernames -split ","

    foreach ($Username in $Usernames)
    {
        $Username = $($Username.trim().ToUpper())
        $IAMUserExists = Get-IAMUsers -ProfileName $ProfileName | where {$_.UserName -eq $Username }

        if ($IAMUserExists)
        {
            write-verbose "IAM User:$Username exists"

            $UserExists = $True
            $DateCreated = $($IAMUserExists.CreateDate)
            $Path = $($IAMUserExists.path)
            $MemberOfGroups = $((Get-IAMGroupForUser $UserName -ProfileName $ProfileName).groupName -join(","))

            if(!($MemberOfGroups))
            {
                $MemberOfGroups = 'N/A'
            }
            
            $Key = $((Get-IAMAccessKey $UserName -ProfileName $ProfileName).accesskeyid -join(","))

            if ($Key)
            {
                $APIAccess = $True
            }

            else 
            {
                $Key = 'N/A'
                $APIAccess = $False
            }

            Try
            {
                $Console = Get-IAMLoginProfile -UserName $Username -ProfileName $ProfileName
                $ConsoleAccess = $True
            }

            Catch
            {
                $ConsoleAccess = $False
            }

            $PasswordLastUsed = $($IAMUserExists.PasswordLastUsed)

            if ($PasswordLastUsed -eq '1/1/0001 12:00:00 AM')
            {
                $PasswordLastUsed = 'N/A'
            }
        }

        else 
        {
            write-verbose "IAM User: $Username does not exist"
            $UserExists = $False
            $DateCreated = 'N/A'
            $PasswordLastUsed = 'N/A'
            $Path = 'N/A'
            $MemberOfGroups = 'N/A'
            $APIAccess = 'N/A'
            $Key = 'N/A'
            $ConsoleAccess = 'N/A'
        } 

        # Return AWS account number
        $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
        $AccountNumber = $Matches[0] 

        $FindIAMUserInfo = [ordered] @{
                                AWSAccountNumber="$AccountNumber";
                                AWSAccountName="$ProfileName";
                                UserName="$UserName";
                                UserExists="$UserExists";
                                DateCreated="$DateCreated";
                                Path="$Path";
                                MemberOfGroups="$MemberOfGroups";
                                ConsoleAccess="$ConsoleAccess";
                                PasswordLastUsed="$PasswordLastUsed";                                
                                APIAccess="$APIAccess";
                                Keys="$Key";                                
                            }

        $FindIAMUserObj = New-Object -Type PSObject -Prop $FindIAMUserInfo 
        $FindIAMUsers += $FindIAMUserObj              
    }
    
    $FindIAMUsers
}
<#
.SYNOPSIS
    Creates new IAM user account(s)
.DESCRIPTION
    Creates new IAM user account(s), setting path, generating keys and configuring console access if required. Returns a custom PS object for each user created. Users are provisioned in the default AWS account.
.PARAMETER UserNames
    The usernames of the new accounts. The username should match the ADS domain account name. For the creation of multiple accounts use a comma seperated list. (e.g TESTA,TESTB). If you create multiple users they will all be added to the same groups specified in MemberOfGroups.
.PARAMETER AddToGroups
    The IAM groups that the user will be added to. For addition to multiple groups use a comma seperated list. (e.g A360_Users,A360_Manage_Own_Credentials) 
.PARAMETER Path
    The path that will be assigned to the IAM user. This is used to differentiate user accounts during auditing (if the path is not set, the account was likely created manually and will likely not be configured correctly). Path 
    can also be used to differentiate between users and service accounts if desired. The default path is '/A360/'.
.PARAMETER NoAPIAccess
    If the switch 'NoAPIAccess' is set then the account will be provisioned without a key pair for API access. Some users may only require console access.
.PARAMETER ConsoleAccess
    If the switch 'ConsolAaccess' is set then the account will be provisioned with console access, and a complex password configured. The output object will also contain the password and URL to log into the console generated from either the AWS Account alias (if it exists) or the account number. This is only required for user access, not for service accounts.
.PARAMETER Passwordlength
    The length of the password for the IAM user if console access is being provisioned. Default value will be set to 12 charecters. Complexity is also enabled.
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns $NewIAMUsers which is an array of PS objects containing the following information:
    AWSAccountNumber:       The AWS account number that contains the IAM user.
    AWSAccountName:         The AWS account name that contains the IAM user.
    UserName:               The username of the IAM user being created.
    UserExists:             True/False as to whether the user already exists.
    Path:                   The path of the IAM user.
    AddedToGroups:          The names of the IAM groups the new user is being added to.
    APIAccess:              Whether API Keys were created.
    Key:                    The key of the API key pair for the user.
    Secret:                 The secret of the API key pair for the user.
    ConsoleAccess:          True/False as to whether console access is provisioned for the user.
    ConsolePassword:        The complex password generated for users console access.
    ConsoleURL:             The URL used to access the AWS account console.
.NOTES
    NAME......:  New-AWSIAMUser
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    New-AWSIAMUser -Usernames 'MYUSER' -AddToGroups 'A360_Users'
    Checks for the IAM account MYUSER, if it is not found, creates the IAM User using the default Userpath (/A360/) and adds the user to IAM group A360_Users.
.EXAMPLE
    New-AWSIAMUser -Username 'MYUSER,MYUSER1,MYUSER2' -AddToGroups 'A360_PowerUsers'
    Checks for the IAM accounts MYUSER,MYUSER1,MYUSER2 if any of the accounts are not found, creates the IAM User using the default Userpath (/A360/) and adds the user to IAM group A360_PowerUsers.
.EXAMPLE
    New-AWSIAMUser -Username 'MYUSER4' -AddToGroups 'A360_PowerUsers' -ConsoleAccess
    Checks for the IAM accounts MYUSER4, if it is not found, creates the IAM User using the default Userpath (/A360/) and adds the user to IAM group A360_PowerUsers. In addition generates a complex password for console access and generates the console URL.
#>
function New-AWSIAMUser
{
    [CmdletBinding()]
    Param ( 
        [Parameter(Mandatory=$true,HelpMessage="Enter the usernames of the new IAM users you want to create. The username should match the ADS domain account name. For the creation of multiple accounts use a comma seperated list. (e.g TESTA,TESTB). If you enter multiple user names, they will all be created with the same parameters (ie added to same groups, granted console access etc)")]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Usernames,  

        [Parameter(Mandatory=$true,HelpMessage="Enter IAM groups that the user will be added to. For addition to multiple groups use a comma seperated list. (e.g A360_Users,A360_Manage_Own_Credentials)")]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $AddToGroups,

        [Parameter(Mandatory=$false,HelpMessage="Enter the path for the IAM user, this is used to distinguish different account types. Default value will be set to '/A360/'")]
        [ValidateNotNullOrEmpty()]
        [string]
        $UserPath = '/A360/',  

        [Parameter(Mandatory=$false,HelpMessage="If the switch 'NoAPIAccess' is set then the account will be provisioned without a key pair for API access. Some users may only need console access.")]
        [Switch]
        $NoAPIAccess,

        [Parameter(Mandatory=$false,HelpMessage="If the switch 'ConsolAaccess' is set then the account will be provisioned with console access, and a complex password configured. The output object will also contain the password and URL to log into the console generated from either the AWS Account alias (if it exists) or the account number. This is only required for user access, not for service accounts.")]
        [Switch]
        $ConsoleAccess,

        [Parameter(Mandatory=$false,HelpMessage="Enter the length of the password for the IAM user if console access is being provisioned. Default value will be set to 12 charecters. Complexity is also enabled.")]
        [Int]
        $Passwordlength = '12',

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName  
    ) 
    # Empty array to add PS objects to and return new IAM user information.
    $NewIAMUsers = @()
    
    # Split array of usernames and loop through each, trimming input to remove spaces, convert to uppercase, check whether IAM user exists and if not creating a new user.
    $Usernames = $Usernames -split ","

    foreach ($Username in $Usernames)
    {
        $Username = $($Username.trim().ToUpper())
        $IAMUserExists = Get-IAMUsers -ProfileName $ProfileName | where {$_.UserName -eq $Username }

        if ($IAMUserExists)
        {
            write-verbose "IAM User:$Username exists"
            $Host.UI.WriteErrorLine("`nUnable to create new IAM user: $Username, user already exists.`n")
            $UserExists = $True
            $Userpath = "$($IAMUserExists.path)"
            $Userpath = 'N/A'
            $AddedToGroups = 'N/A'
            if(!($AddToGroups))
            {
                $AddedToGroups = 'N/A'
            }
            
            $Key = $((Get-IAMAccessKey $UserName -ProfileName $ProfileName).accesskeyid -join(","))

            if ($Key)
            {
                $APIAccess = $True
            }            
            
            else 
            {
                $Key = 'N/A'
                $APIAccess = $False
            }

            Try
            {
                $Console = Get-IAMLoginProfile -UserName $Username -ProfileName $ProfileName
                $ConsoleAccess = $True
            }

            Catch
            {
                $ConsoleAccess = $False
            }

            $Password = 'N/A'
            $URL = 'N/A'


            $PasswordLastUsed = $($IAMUserExists.PasswordLastUsed)

            if ($PasswordLastUsed -eq '1/1/0001 12:00:00 AM')
            {
                $PasswordLastUsed = 'NEVER'
            }            

            $Secret = 'N/A'        
        }

        else 
        {
            write-verbose "IAM User: $Username does not exist"
            
            Try
            {
                # Create user and retrieve IAM keys
                $NewUser = New-IAMUser -Path $UserPath -UserName $Username -ProfileName $ProfileName
                $Secret = New-IAMAccessKey -UserName $UserName -ProfileName $ProfileName | Select -Expand SecretAccessKey
                $Key = Get-IAMAccessKey $UserName -ProfileName $ProfileName | Select -Expand AccessKeyID
                write-verbose "Created new IAM user: $UserName Path: $Userpath"
                write-verbose "Created key: $Key for: $UserName"
                $UserExists = $False
                $APIAccess = $True
            }
            
            Catch
            {
                $Host.UI.WriteErrorLine("`nUnable to create new IAM User.`n$_.error`n")
                $NewUser = "USER $Username NOT CREATED: $_.error"
            } 

        # Add to IAM groups
        if ($AddToGroups)
        {
            $AddedToGroups = @()
            $NotAddedToGroups = @()
            $SplitAddToGroups = $AddToGroups -split "," 
        
            foreach ($AddToGroup in $SplitAddToGroups)
            {           
                $AddToGroup = $($AddToGroup.trim())

                $AlreadyMember = Get-IAMGroupForUser -UserName $Username -ProfileName $ProfileName | where {$_.GroupName -eq $AddToGroup }

                if ($AlreadyMember)
                {
                    $NotAddedToGroups += $AddToGroup + ' (Already Member)'
                }

                else 
                {
                    $GroupExist = Get-IAMGroups -ProfileName $ProfileName | where {$_.GroupName -eq $AddToGroup }

                    if ($GroupExist)
                    {
                        Try
                        {
                            Add-IAMUserToGroup -UserName $Username -GroupName $AddToGroup -ProfileName $ProfileName
                            write-verbose "Added IAM User to Group: $AddToGroup"
                            $AddedToGroups += $AddToGroup
                        }

                        Catch
                        {
                            $Host.UI.WriteErrorLine("`nUnable to add IAM User to group: $AddToGroup.`n$_.error`n")
                            $NotAddedToGroups += $AddToGroup + " (Error: $_.error)"
                        } 
                    }
                    
                    else 
                    {
                        $Host.UI.WriteErrorLine("`nUnable to add IAM User to group: $AddToGroup because the group does not exist.`n")
                        $NotAddedToGroups += $AddToGroup + ' (Does Not Exist)'
                    }
                }            
            }

            $AddedToGroups = $AddedToGroups -join ","
            $NotAddedToGroups = $NotAddedToGroups -join ","

            if (!($AddedToGroups))
            {
                $AddedToGroups = 'N/A'
            }
        }

        else 
        {
            $AddedToGroups = 'N/A'
            $NotAddedToGroups = 'N/A'
        }
        
            if ($NoAPIAccess)
            {        
                Try 
                {  
                    Remove-IAMAccessKey -UserName $Username -AccessKeyId $Key -ProfileName $ProfileName -Force
                    write-verbose "Removed API key: $Key for IAM User: $Username"
                    $APIAccess = $False
                    $Secret = ' - '
                    $Key = ' - '
                }

                Catch
                {
                    $Host.UI.WriteErrorLine("`nUnable to remove key: $Key.`n$_.error`n")
                }
            }

            if ($ConsoleAccess)
            {        
                Try 
                {     
                    # Generate random password, set console access        
                    $Password = New-RandomComplexPassword -Length $Passwordlength
                    $Console = New-IAMLoginProfile -UserName "$Username" -Password "$password" -ProfileName $ProfileName
                    write-verbose "Created console profile for IAM User: $UserName"
                }

                Catch
                {
                    $Host.UI.WriteErrorLine("`nUnable to create console access.`n$_.error`n")
                    $Password = "NOT CREATED: $_.error"
                }

                $Alias = Get-IAMAccountAlias -ProfileName $ProfileName
                
                if ($Alias)
                {
                    $URL = "https://" + $Alias + ".signin.aws.amazon.com/console"
                }

                else 
                {
                    $URL = "https://" + $AccountNumber + ".signin.aws.amazon.com/console"
                }

                write-verbose "Console URL: $URL"
            }

            else 
            {
                $Password = 'No Console Access'
                $URL = 'No Console URL'
            }

        }

        # Return AWS account number
        $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
        $AccountNumber = $Matches[0] 
        
        $NewIAMUserInfo = [ordered] @{
                                AWSAccountNumber="$AccountNumber";
                                AWSAccountName="$ProfileName";
                                UserName="$UserName";
                                UserExists="$UserExists";
                                Path="$Userpath";
                                AddedToGroups="$AddedToGroups";
                                NotAddedToGroups="$NotAddedToGroups";
                                APIAccess="$APIAccess";
                                Key="$Key";
                                Secret="$Secret";
                                ConsoleAccess="$ConsoleAccess"
                                ConsolePassword="$Password";
                                ConsoleURL="$URL"
                            }
        $NewIAMUserObj = New-Object -Type PSObject -Prop $NewIAMUserInfo
        $NewIAMUsers += $NewIAMUserObj
    }

    $NewIAMUsers
}
<#
.SYNOPSIS
    Removes IAM User(s).
.DESCRIPTION
    Removes IAM user(s) from an AWS account. This is a multi-step process that requires deletion of all existing keys,groups,policies and login profiles before removing the account.
.PARAMETER UserName
    The name of the IAM user who will be deleted. 
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns $DeletedIAMUserObj which is a PS object containing the following information:
    AWSAccountNumber:       The AWS account number that contains the IAM user.
    AWSAccountName:         The AWS account name that contains the IAM user.
    UserName:               The username of the IAM user the keys are being replaced for.
    Keys:                   The keys that were deleted for the IAMuser.
    Groups:                 The groups that the IAM user was removed from.
    Policies:               The policies that the IAM user was removed from.
    LoginProfile:           The date that the login profile was created and which was deleted.

.NOTES
    NAME......:  Remove-AWSIAMUser
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    Remove-AWSIAMUsers -Username 'MYUSER' 
    For the IAM user 'MYUSER' checks for any existing keys, groups, policies and login profiles. If any are found,
    deleted them before deleting the user account.
#>
function Remove-AWSIAMUser
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the IAM user you want to delete.")]
        [string[]] 
        $Usernames,

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    ) 
    # Empty array to add PS objects to and return new IAM user information.
    $RemovedIAMUsers = @()
    
    # Split array of usernames and loop through each, trimming input to remove spaces, convert to uppercase, check whether IAM user exists and if not creating a new user.
    $Usernames = $Usernames -split ","

    foreach ($Username in $Usernames)
    {
        $Username = $($Username.trim().ToUpper())
        $IAMUserExists = Get-IAMUsers -ProfileName $ProfileName | where {$_.UserName -eq $Username }

        if ($IAMUserExists)
        {
            write-verbose "IAM User:$Username exists"
            $UserExists = $True
    
            $Keys = Get-IAMAccessKey $Username -ProfileName $ProfileName | select -expand AccessKeyId

            if ($Keys)
            {
                foreach ($Key in $Keys)
                {
                    Remove-IAMAccessKey $Username -AccessKeyId $Key -ProfileName $ProfileName -force
                    write-verbose "Removed key: $Key for IAM user: $UserName"
                }
            }

            else 
            {
                $Keys = 'None'
                write-verbose "No keys found for IAM User: $UserName"
            }

            $Groups = Get-IAMGroupForUser $Username -ProfileName $ProfileName | select -expand GroupName

            if ($Groups)
            {
                foreach ($Group in $Groups)
                {
                    Remove-IAMUserFromGroup $Group -username $Username -ProfileName $ProfileName -force
                    write-verbose "Removed IAM User: $UserName from group: $Group"
                }
            }

            else 
            {
               $Groups = 'None'
               write-verbose "IAM User: $UserName was not a member of any groups" 
            }

            $Policies = Get-IAMUserPolicies $Username -ProfileName $ProfileName

            if ($Policies)
            {
                foreach ($Policy in $Policies)
                {
                    Remove-IAMUserPolicy -ProfileName $ProfileName -username $Username -PolicyName $Policy -force
                    write-verbose "Removed IAM User: $UserName from policy: $Policy"
                }
            }

            else 
            {
               $Policies = 'None'
               write-verbose "IAM User: $UserName was not a member of any policies"
            }

            Try
            {
                $LoginProfile = Get-IAMLoginProfile $Username -ProfileName $ProfileName | select -expand CreateDate
            
                if ($LoginProfile)
                {
                    Remove-IAMLoginProfile $Username -ProfileName $ProfileName -force
                    write-verbose "Removed console profile for IAM User: $UserName"
                }
            }

            Catch
            {
                $LoginProfile = 'N/A'
                write-verbose "IAM User: $UserName did not have a console profile"
            }

            Remove-IAMUser $Username -ProfileName $ProfileName -force
            write-verbose "Removed IAM User: $UserName"
        }

        else 
        {
            write-verbose "IAM User: $Username does not exist"
            $Host.UI.WriteErrorLine("`nUnable to remove IAM User: $Username, the user does not exist`n")
            $UserExists = $False
            $Keys = 'N/A'
            $Groups = 'N/A'
            $Policies = 'N/A'
            $LoginProfile = 'N/A'
        }

        # Return AWS account number
        $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
        $AccountNumber = $Matches[0] 

        $RemovedIAMUserInfo = [ordered]  @{
                                AWSAccountNumber="$AccountNumber";
                                AWSAccountName="$ProfileName";
                                UserName="$UserName";
                                UserExists="$UserExists";
                                RemovedKeys="$Keys";
                                RemovedFromGroups="$Groups";
                                RemovedFromPolicies="$Policies";
                                ConsoleProfile="$LoginProfile"                                
                        }

        $RemovedIAMUserObj = New-Object -Type PSObject -Prop $RemovedIAMUserInfo 
        $RemovedIAMUsers += $RemovedIAMUserObj
    }

    $RemovedIAMUsers   
}
<#
.SYNOPSIS
    Updates existing IAM user.
.DESCRIPTION
    Updates existing IAM user, based on input parameters updates UserName,Path,Group Membership (add or remove)
.PARAMETER UserName
    The usernames of the new accounts. The username should match the ADS domain account name. For the creation of multiple accounts use a comma seperated list. (e.g TESTA,TESTB). If you create multiple users they will all be added to the same groups specified in MemberOfGroups.
.PARAMETER NewUserPath
    The path that will be assigned to the IAM user. This is used to differentiate user accounts during auditing (if the path is not set, the account was likely created manually and will likely not be configured correctly). Path 
    can also be used to differentiate between users and service accounts if desired. The default path is '/A360/'.
.PARAMETER AddToGroups
    The IAM groups that the user will be added to. For addition to multiple groups use a comma seperated list. (e.g A360_Users,A360_Manage_Own_Credentials) 
.PARAMETER RemoveFromGroups
    The IAM groups that the user will be added to. For addition to multiple groups use a comma seperated list. (e.g A360_Users,A360_Manage_Own_Credentials)
.PARAMETER RemoveFromPolicies
    If the switch 'RemoveFromPolicies' is set then the IAM user will have all attached policies removed.
.PARAMETER RemoveKeys
    If the switch 'RemoveAPIAccess' is set then any API keys that have been issued to the IAM user will be deleted.
.PARAMETER NewKey
    If the switch 'NewKey' is set then the creates new IAM access key for IAM User. If there are existing keys they are all deleted.
.PARAMETER ConsoleAccess
    If the switch 'ConsoleAccess' is set then the IAM user will be provisioned with console access, and a complex password configured. The output object will also contain the password and URL to log into the console generated from either the AWS Account alias (if it exists) or the account number. This is only required for user access, not for service accounts.
.PARAMETER ResetConsolePassword
    If the switch 'ResetConsolePassword' is set then the IAM users console password will be reset and new a complex password configured.
.PARAMETER Passwordlength
    The length of the password for the IAM user if console access is being provisioned (default value is 12 characters and complexity enabled)
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns $UpdateIAMUserObj which is a PS object containing the following information:
    AWSAccountNumber:       The AWS account number that contains the IAM user.
    AWSAccountName:         The AWS account name that contains the IAM user.
    UserName:               The username of the IAM user being updated.
    NewUsername:            The new username of the IAM user being updated. 
    UserExists
    NewUserPath:            The new path of the IAM user being updated.
    AddedToGroups:          The names of the IAM groups the IAM user is being added to.
    RemovedFromGroups:      The names of the IAM groups the IAM user is being removed from.
    RemoveFromPolicies:     Removes all policies attached to an IAM User.
    RemovedAPIAccess:       Removes all API keys from the IAM user.
    Key:                    The key of the API key pair for the IAM user.
    Secret:                 The secret of the API key pair for the IAM user.
    ConsolePassword:        The complex password generated for IAM users console access.
    ConsoleURL:             The URL used to access the AWS account console.
.NOTES
    NAME......:  Update-AWSIAMUser
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    Update-AWSIAMUser -Usernames 'MYUSER' -RemoveFromGroups 'A360_Users'
    Checks that the IAM user MYUSER, if it is not found, creates the IAM User using the default Userpath (/A360/) and adds the user to IAM group A360_Users.
.EXAMPLE
    Update-AWSIAMUser -Username 'MYUSER,MYUSER1,MYUSER2' -AddToGroups 'A360_PowerUsers'
    Checks that the IAM users MYUSER,MYUSER1,MYUSER2 exist and if it does adds the IAM user to IAM group A360_PowerUsers.
.EXAMPLE
    Update-AWSIAMUser -Username 'MYUSER4' -ConsoleAccess
    Verifies that the IAM user MYUSER4 exists and creates a console profile a complex password and finds the console URL.
#>
function Update-AWSIAMUser
{
    [CmdletBinding()]
    Param ( 
        [Parameter(Mandatory=$true,HelpMessage="Enter the usernames of the existing IAM user that you are updating.")]
        [ValidateNotNullOrEmpty()]
        [string]
        $Username,  

        [Parameter(Mandatory=$false,HelpMessage="Enter the new name for the existing IAM User to be updated.")]
        [ValidateNotNullOrEmpty()]
        [string]
        $NewUsername,

        [Parameter(Mandatory=$false,HelpMessage="Enter the new path for the IAM user, this is used to distinguish different account types. Default value will be set to '/A360/'")]
        [ValidateNotNullOrEmpty()]
        [string]
        $NewUserPath = "/A360/", 

        [Parameter(Mandatory=$false,HelpMessage="Enter IAM groups that the user will be added to. For addition to multiple groups use a comma seperated list. (e.g A360_Users,A360_Manage_Own_Credentials)")]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $AddToGroups, 

        [Parameter(Mandatory=$false,HelpMessage="Enter IAM groups that the user will be removed from. For removal from multiple groups use a comma seperated list. (e.g A360_Users,A360_Manage_Own_Credentials)")]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $RemoveFromGroups, 

        [Parameter(Mandatory=$false,HelpMessage="If the switch 'RemoveFromPolicies' is set then the IAM user will have all attached policies removed from the user.")]
        [ValidateNotNullOrEmpty()]
        [switch]
        $RemoveFromPolicies,

        [Parameter(Mandatory=$false,HelpMessage="If the switch 'RemoveKeys' is set then any API keys that have been issued to the IAM user will be deleted.")]
        [Switch]
        $RemoveKeys,

        [Parameter(Mandatory=$false,HelpMessage="If the switch 'NewKey' is set then the creates new IAM access key for IAM User. If there are existing keys they are all deleted.")]
        [Switch]
        $NewKey,

        [Parameter(Mandatory=$false,HelpMessage="If the switch 'ConsoleAccess' is set then the IAM user will be provisioned with console access. This is only required for user access, not for service accounts.")]
        [Switch]
        $ConsoleAccess,

        [Parameter(Mandatory=$false,HelpMessage="If the switch 'ResetConsolePassword' is set then the IAM users console password will be reset.")]
        [Switch]
        $ResetConsolePassword,

        [Parameter(Mandatory=$false,HelpMessage="Enter the length of the password for the IAM user if console access is being provisioned or password reset (default value is 12 characters and complexity enabled)")]
        [Int]
        $Passwordlength = "12",

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName     
    )

    # Trim any leading or trailing spaces, convert to uppercase
    $Username = $($Username.trim().ToUpper())
    write-verbose "Checking to see whether IAM user: $Username Exists"

    $IAMUserExists = Get-IAMUsers -ProfileName $ProfileName | where {$_.UserName -eq $Username }  

    if ($IAMUserExists)
    {
        $UserExists = $True

        if ($NewUsername)
        {
            if ($($Username).username -ne $NewUsername)
            {
                Update-IAMUser -UserName $UserName -NewUserName $NewUsername -ProfileName $ProfileName
                $OldUsername = $UserName
                $Username = $NewUsername
                write-verbose "Updated IAM user: $OldUsername name to: $NewUsername"
            } 
        }

        else 
        {
            $NewUsername = 'N/A'
        }

        # Update IAM user path
        if ($($IAMUserExists.path) -ne $NewUserPath)
        {
            $($IAMUserExists.path)
            write-verbose "Updating IAM User path to: $NewUserPath"
            Update-IAMUser -UserName $UserName -Newpath $NewUserPath -ProfileName $ProfileName
        } 

        else 
        {
            $NewUserPath = 'N/A'
        }

        # Add to IAM groups
        if ($AddToGroups)
        {
            $AddedToGroups = @()
            $NotAddedToGroups = @()
            $SplitAddToGroups = $AddToGroups -split "," 
        
            foreach ($AddToGroup in $SplitAddToGroups)
            {           
                $AddToGroup = $($AddToGroup.trim())

                $AlreadyMember = Get-IAMGroupForUser -UserName $Username -ProfileName $ProfileName | where {$_.GroupName -eq $AddToGroup }

                if ($AlreadyMember)
                {
                    $NotAddedToGroups += $AddToGroup + ' (Already Member)'
                }

                else 
                {
                    $GroupExist = Get-IAMGroups -ProfileName $ProfileName | where {$_.GroupName -eq $AddToGroup }

                    if ($GroupExist)
                    {
                        Try
                        {
                            Add-IAMUserToGroup -UserName $Username -GroupName $AddToGroup -ProfileName $ProfileName
                            write-verbose "Added IAM User to Group: $AddToGroup"
                            $AddedToGroups += $AddToGroup
                        }

                        Catch
                        {
                            $Host.UI.WriteErrorLine("`nUnable to add IAM User to group: $AddToGroup.`n$_.error`n")
                            $NotAddedToGroups += $AddToGroup + " (Error: $_.error)"
                        } 
                    }
                    
                    else 
                    {
                        $Host.UI.WriteErrorLine("`nUnable to add IAM User to group: $AddToGroup because the group does not exist.`n")
                        $NotAddedToGroups += $AddToGroup + ' (Does Not Exist)'
                    }
                }            
            }

            $AddedToGroups = $AddedToGroups -join ","
            $NotAddedToGroups = $NotAddedToGroups -join ","

            if (!($AddedToGroups))
            {
                $AddedToGroups = 'N/A'
            }
        }

        else 
        {
            $AddedToGroups = 'N/A'
            $NotAddedToGroups = 'N/A'
        }

        # Remove from IAM groups
        if ($RemoveFromGroups)
        {
            $RemoveFromGroups = $RemoveFromGroups -split ","
        
            foreach ($RemoveFromGroup in $RemoveFromGroups)
            {           
                $RemoveFromGroup = $($RemoveFromGroup.trim())                
                $GroupExist = Get-IAMGroups -ProfileName $ProfileName | where {$_.GroupName -eq $AddToGroup }
                
                if ($GroupExist)
                {
                    Try
                    {
                        Remove-IAMUserFromGroup -GroupName $RemoveFromGroup -UserName $Username -ProfileName $ProfileName -Force
                        write-verbose "Removing User from Group: $RemoveFromGroup"
                    }

                    Catch
                    {
                        $Host.UI.WriteErrorLine("`nUnable to remove user from group: $RemoveFromGroup.`n$_.error`n")
                    } 
                }

                else 
                {
                    $Host.UI.WriteErrorLine("`nUnable to remove user from group: $RemoveFromGroup because the group does not exist.`n")
                }            
            }
        }

        else 
        {
            $RemoveFromGroups = 'N/A'
        }

        # Delete any policies attached to user
        if ($RemoveFromPolicies)
        {
            $RemovedFromPolicies = Get-IAMUserPolicies -UserName $Username -ProfileName $ProfileName
        
            foreach ($RemoveFromPolicy in $RemoveFromPolicies)
            {           
                Try
                {
                    write-verbose "Removing User from Policy: $RemoveFromPolicy"
                    Remove-IAMUserPolicy -UserName $Username -PolicyName $RemoveFromPolicy -ProfileName $ProfileName -Force
                }

                Catch
                {
                    $Host.UI.WriteErrorLine("`nUnable to remove user from policy: $RemoveFromPolicy .`n$_.error`n")
                    Return
                }            
            }
        }

        else 
        {
            $RemovedFromPolicies = 'N/A'
        }

        if ($RemoveKeys)
        {
            $RemovedKeys = @()

            Try
            {
                # Get list of existing keys, delete if found
                $Keys = Get-IAMAccessKey -UserName $UserName -ProfileName $ProfileName | select -expand AccessKeyId

                if ($Keys)
                {
                    foreach ($Key in $Keys)
                    {
                        Remove-IAMAccessKey -UserName $UserName -AccessKeyId $Key -ProfileName $ProfileName -force
                        write-verbose "Deleting key: $Key for User: $UserName"
                        $RemovedKeys += $Key
                    }

                    $RemovedKeys = $RemovedKeys -join ","
                }

                else 
                {
                    write-verbose "No keys found for User: $UserName"
                    $RemovedKeys = "No Keys Found"
                }
            }

            Catch
            {
                $Host.UI.WriteErrorLine("`nUnable to find keys.`n$_.error`n")
                $RemovedKeys = "Unable to Remove Keys: $_.error"
            }
        }

        else 
        {
            $RemovedKeys = 'N/A'
        }

        # Delete existing keys and create new
        if ($NewKey)
        {    
            Try
            {
                # Get list of existing keys, delete if found
                $Keys = Get-IAMAccessKey -UserName $UserName -ProfileName $ProfileName | select -expand AccessKeyId

                if ($Keys)
                {
                    foreach ($Key in $Keys)
                    {
                        Remove-IAMAccessKey -UserName $UserName -AccessKeyId $Key -ProfileName $ProfileName -force 
                        write-verbose "Deleting key: $Key for User: $UserName"
                    }
                }

                # Create new key
                $Secret = New-IAMAccessKey -UserName $UserName | Select -expand SecretAccessKey -ProfileName $ProfileName
                $Key = Get-IAMAccessKey -UserName $UserName -ProfileName $ProfileName | select -expand AccessKeyId 
                write-verbose "Generated new key: $Key for IAM User: $UserName" 
            }

            Catch
            {
                $Host.UI.WriteErrorLine("`nUnable to retrieve keys.`n$_.error`n")
            }
        }

        else 
        {
            $Secret = 'N/A'
            $Key = 'N/A'
        }

        # Create console profile and set password, URL
        if ($ConsoleAccess)
        {        
            Try
            {
                $ExistingProfile = Get-IAMLoginProfile -UserName $Username -ProfileName $ProfileName
                $Password = 'User already has console access' 
                write-verbose "IAM user already has console access"
            }

            Catch
            {
                write-verbose "IAM user does not have console access, creating password."

                Try 
                {     
                    # Generate random password, set console access        
                    $Password = New-RandomComplexPassword -Length $Passwordlength
                    $ConsoleAccess = New-IAMLoginProfile -UserName "$Username" -Password "$password" -ProfileName $ProfileName
                    write-verbose "Created new console profile and set password"
                }

                Catch
                {
                    $Host.UI.WriteErrorLine("`nUnable to set console access.`n$_.error`n")
                    $Password = "Error setting console password : $_.error"
                }
            }
        }

        # Create console profile and set password, URL
        if ($ResetConsolePassword)
        { 
            Try
            {
                $ExistingProfile = Get-IAMLoginProfile -UserName $Username -ProfileName $ProfileName

                Try 
                {  
                    $Password = New-RandomComplexPassword -Length $Passwordlength
                    $NewPassword = Update-IAMLoginProfile -UserName $Username -Password $Password -ProfileName $ProfileName
                    write-verbose "Reset IAM users password"                
                }

                Catch
                {
                    $Host.UI.WriteErrorLine("`nUnable to set console access.`n$_.error`n")
                    $Password = "Error setting console password : $_.error"
                }
            }

            Catch
            {
                write-verbose "IAM user does not have console access, unable to reset password"
            }
        }

        if ($ResetConsolePassword -or $ConsoleAccess)
        {
            $Alias = Get-IAMAccountAlias -ProfileName $ProfileName
            
            if ($Alias)
            {
                $URL = "https://" + $Alias + ".signin.aws.amazon.com/console"
            }

            else 
            {
                $URL = "https://" + $AccountNumber + ".signin.aws.amazon.com/console"
            }

            write-verbose "Console URL: $URL"
        }

        else 
        {
            $Password = 'N/A'
            $URL = 'N/A'
        }

        if ($OldUsername)
        {
            $Username = $OldUsername
        }
    }

    Else
    {
        $Host.UI.WriteErrorLine("`nUnable to update IAM user: $Username, user does not exist`n")
        $UserExists = $False
        $NewUserName = 'N/A'
        $NewUserPath = 'N/A'
        $AddedToGroups = 'N/A'
        $RemoveFromGroups = 'N/A'
        $RemovedFromPolicies = 'N/A'
        $RemovedKeys = 'N/A'
        $URL = 'N/A'
        $Password = 'N/A'
        $Key = 'N/A'
        $Secret = 'N/A'
    }  

    # Return AWS account number
    $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
    $AccountNumber = $Matches[0] 

    $UpdateIAMUserInfo = [ordered]  @{
                                AWSAccountNumber="$AccountNumber";
                                AWSAccountName="$ProfileName";
                                UserName="$UserName";
                                NewUserName="$NewUserName"
                                UserExists="$UserExists";
                                NewUserPath="$NewUserPath";
                                AddedToGroups="$AddedToGroups";
                                NotAddedToGroups="$NotAddedToGroups";
                                RemovedFromGroups="$RemoveFromGroups";
                                RemovedFromPolicies="$RemovedFromPolicies";
                                RemovedKeys="$RemovedKeys"
                                ConsoleURL="$URL";
                                ConsolePassword="$Password";
                                Key="$Key";
                                Secret="$Secret"
                            }                                

    $UpdateIAMUserObj = New-Object -Type PSObject -Prop $UpdateIAMUserInfo
    $UpdateIAMUserObj  
}  
<#
.Synopsis
    Creates a complex, random password
.DESCRIPTION
    Returns a complex, random password based on input paramaters to define length and complexity.
.PARAMETER Length 
    The length of the new password being created (number of characters total). (default value is 12).
.PARAMETER IncludeLowercaseLetters
    Include lowercase letters in the new password being created. (default value is true)
.PARAMETER IncludeUppercaseLetters 
    Include uppercase letters in the new password being created. (default value is true)
.PARAMETER IncludeNumbers
    Include numbers in the new password being created. (default value is true)
.PARAMETER IncludeSpecialChars
    Include special charecters (= + _ ? ! - # * & @ % ) in the new password being created.
.PARAMETER NoSimilarCharacters
    Remove similar charecters (i, l, o, 1, 0, I) in new password being created? (default value is true)
.OUTPUTS
    Returns $Password which is a string containing the new random,complex password.
.EXAMPLE
    New-RandomComplexPassword -Length 10
    Creates a new random, complex password that is 10 characters long using the pre-defined defaults (include lowercase, uppercase, numbers, special characters and no similar characters)
.NOTES
    Script based on: http://blog.morg.nl/2014/01/generate-a-random-strong-password-in-powershell/
    (c) Morgan de Jonge CC BY SA
#>
function New-RandomComplexPassword
{
    [CmdletBinding()]
    Param (

    [Parameter(Mandatory=$false,HelpMessage="Enter length (number of charecters) of the new password being created (default value is 12 and minimum length is 10).")]
    [ValidateNotNullOrEmpty()]
    [int]
    $Length = '12',

    [Parameter(Mandatory=$false,HelpMessage="Use lower-case charecters in new password? (default value is true).")]
    [ValidateNotNullOrEmpty()]    
    [bool] 
    $IncludeLowercaseLetters = $true,

    [Parameter(Mandatory=$false,HelpMessage="Use upper-case charecters in new password? (default value is true).")]
    [ValidateNotNullOrEmpty()]    
    [bool] 
    $IncludeUppercaseLetters = $true,

    [Parameter(Mandatory=$false,HelpMessage="Use numbers in new password? (default value is true).")]
    [ValidateNotNullOrEmpty()]    
    [bool] 
    $IncludeNumbers = $true,

    [Parameter(Mandatory=$false,HelpMessage="Use special charecters (= + _ ? ! - # * & @ % ) in new password? (default value is true).")]
    [ValidateNotNullOrEmpty()]    
    [bool] 
    $IncludeSpecialChars = $true,

    [Parameter(Mandatory=$false,HelpMessage="Remove similar charecters (i, l, o, 1, 0, I) in new password? (default value is true).")]
    [ValidateNotNullOrEmpty()]    
    [bool] 
    $NoSimilarCharacters  = $true
    )
 
    # Validate params
    if($length -lt 10) 
    {
        $exception = New-Object Exception "The minimum password length is 8"
        Throw $exception
    }

    if ($includeLowercaseLetters -eq $false -and 
            $includeUppercaseLetters -eq $false -and
            $includeNumbers -eq $false -and
            $includeSpecialChars -eq $false) 
    {
        $exception = New-Object Exception "At least one set of included characters must be specified"
        Throw $exception
    }
 
    #Available characters
    $CharsToSkip = [char]"i", [char]"l", [char]"o", [char]"1", [char]"0", [char]"I"
    $AvailableCharsForPassword = $null;
    $uppercaseChars = $null 
    for($a = 65; $a -le 90; $a++) { if($noSimilarCharacters -eq $false -or [char][byte]$a -notin $CharsToSkip) {$uppercaseChars += ,[char][byte]$a }}
    $lowercaseChars = $null
    for($a = 97; $a -le 122; $a++) { if($noSimilarCharacters -eq $false -or [char][byte]$a -notin $CharsToSkip) {$lowercaseChars += ,[char][byte]$a }}
    $digitChars = $null
    for($a = 48; $a -le 57; $a++) { if($noSimilarCharacters -eq $false -or [char][byte]$a -notin $CharsToSkip) {$digitChars += ,[char][byte]$a }}
    $specialChars = $null
    $specialChars += [char]"=", [char]"+", [char]"_", [char]"?", [char]"!", [char]"-", [char]"#", [char]"$", [char]"*", [char]"&", [char]"@", [char]"%"
 
    $TemplateLetters = $null
    if($includeLowercaseLetters) 
    { 
        $TemplateLetters += "L" 
    }

    if($includeUppercaseLetters) 
    { 
        $TemplateLetters += "U" 
    }

    if($includeNumbers) 
    { 
        $TemplateLetters += "N" 
    }

    if($includeSpecialChars) 
    { 
        $TemplateLetters += "S" 
    }

    $PasswordTemplate = @()
    
    # Set password template, to ensure that required chars are included
    do {   
        $PasswordTemplate.Clear()
        for($loop = 1; $loop -le $length; $loop++) {
            $PasswordTemplate += $TemplateLetters.Substring((Get-Random -Maximum $TemplateLetters.Length),1)
        }
    }
    while ((
        (($includeLowercaseLetters -eq $false) -or ($PasswordTemplate -contains "L")) -and
        (($includeUppercaseLetters -eq $false) -or ($PasswordTemplate -contains "U")) -and
        (($includeNumbers -eq $false) -or ($PasswordTemplate -contains "N")) -and
        (($includeSpecialChars -eq $false) -or ($PasswordTemplate -contains "S"))) -eq $false
    )
    #$PasswordTemplate now contains an array with at least one of each included character type (uppercase, lowercase, number and/or special)
 
    foreach($char in $PasswordTemplate) 
    {
        switch ($char) {
            L { $Password += $lowercaseChars | Get-Random }
            U { $Password += $uppercaseChars | Get-Random }
            N { $Password += $digitChars | Get-Random }
            S { $Password += $specialChars | Get-Random }
        }
    }
 
    return $Password
}
<#
.SYNOPSIS
    Creates new IAM group.
.DESCRIPTION
    Checks whether group exists and if not creates a new IAM group, setting path correctly.
.PARAMETER GroupName
    The name of the new IAM group being created.
.PARAMETER Path
    The path that will be assigned to the IAM group. This is used to differentiate user accounts during auditing (if the path is not set, the group was likely created manually and will likely not be configured correctly). Path 
    can also be used to differentiate between users and service accounts if desired. The default path is '/A360/'.
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns $NewIAMGroupObj which is a PS object containing the following information:
    AWSAccountNumber:       The AWS account number that contains the IAM user.
    AWSAccountName:         The AWS account name that contains the IAM user.
    GroupName:              The groupname of the new IAM group being created.
    Path:                   The path of the new IAM group.
.NOTES
    NAME......:  New-AWSIAMGroup
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  10/1/14
.EXAMPLE
    New-AWSIAMGroup -Groupname 'MYGROUP'
    Checks for the IAM group MYGROUP, if it is not found, creates the new IAM group using the default path (/A360/).
.EXAMPLE
    New-AWSIAMUser -Username 'MYUSER,MYUSER1,MYUSER2' 
    Search for the IAM accounts MYUSER,MYUSER1,MYUSER2 in the AWS account.
#>
function New-AWSIAMGroup
{
    [CmdletBinding()]
    Param ( 
        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the new IAM group being created.")]
        [ValidateNotNullOrEmpty()]
        [string]
        $GroupName,

        [Parameter(Mandatory=$true,HelpMessage="Enter the path for the new IAM group, this is used to distinguish different account types. Default value will be set to '/A360/'")]
        [ValidateNotNullOrEmpty()]
        [string]
        $IAMPolicyDocument,

        [Parameter(Mandatory=$false,HelpMessage="Enter the path for the new IAM group, this is used to distinguish different account types. Default value will be set to '/A360/'")]
        [ValidateNotNullOrEmpty()]
        [string]
        $GroupPath = "/A360/",

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    )
    # Check whether group exists, if it does not create new group, set path and attach policy
    $GroupExist = Get-IAMGroups -ProfileName $ProfileName | where {$_.GroupName -eq $GroupName }
    
    if ($GroupExist)
    {
        $Host.UI.WriteErrorLine("`nUnable to create IAM Group: $Groupname because the group already exists.`n") 
        $GroupCreated = 'Error: Group Already Exists'
        $IAMPolicyDocument = $False
    }

    else 
    {
        Try
        {
            $Newgroup = New-IAMGroup -GroupName $Groupname -Path $GroupPath -ProfileName $ProfileName
            write-verbose "Created new IAM Group: $Groupname"
            $GroupPath = $($Newgroup.path)
            $GroupCreated = $True

            Try
            {
                $Writepolicy = Write-IamGroupPolicy -GroupName $Groupname -PolicyName $Groupname -PolicyDocument $IAMPolicyDocument -ProfileName $ProfileName
                write-verbose "Added policy to IAM Group:"
                $IAMPolicyDocument = $True
            }

            Catch
            {
                $Host.UI.WriteErrorLine("`nUnable to policy to IAM Group.`n$_.error`n")
                $IAMPolicyDocument = "Error: $_.error"
            }  
        }
        
        Catch
        {
            $Host.UI.WriteErrorLine("`nUnable to create IAM Group.`n$_.error`n")
            $GroupCreated = "Error: $_.error"
            $GroupPath = 'N/A'
        }
    } 

    # Return AWS account number
    $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
    $AccountNumber = $Matches[0] 

    # Add all information to PS Object
    $NewIAMGroupInfo = [ordered] @{
                            AWSAccountNumber="$AccountNumber";
                            AWSAccountName="$ProfileName";
                            GroupName="$Groupname";
                            GroupCreated="$GroupCreated";
                            GroupPath="$GroupPath"
                            AddedPolicy="$IAMPolicyDocument";                            
                        }

    $NewIAMGroupObj = New-Object -Type PSObject -Prop $NewIAMGroupInfo
    $NewIAMGroupObj
}
<#
.SYNOPSIS
    Deletes an IAM group.
.DESCRIPTION
    Checks whether group exists and if it does deletes the group.
.PARAMETER GroupName
    The name of the new IAM group being created.
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns $NewIAMGroupObj which is a PS object containing the following information:
    AWSAccountNumber:       The AWS account number that contains the IAM user.
    AWSAccountName:         The AWS account name that contains the IAM user.
    GroupName:              The name group being removed.
    GroupDeleted:           The outcome of the group deletion.
.NOTES
    NAME......:  Remove-AWSIAMGroup
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  1/30/15
.EXAMPLE
    Remove-AWSIAMGroup -Groupname 'MYGROUP'
    Checks for the IAM group MYGROUP, if it is not found, creates the new IAM group using the default path (/A360/).
.EXAMPLE
    Remove-AWSIAMGroup -GroupName 'MYUSER,MYUSER1,MYUSER2' -ProfileName 'MyAWSAccount'
    Search for the IAM accounts MYUSER,MYUSER1,MYUSER2 using the profile MyAWSAccount
#>
function Remove-AWSIAMGroup
{
    [CmdletBinding()]
    Param ( 
        [Parameter(Mandatory=$false,HelpMessage="Enter the name(s) of the IAM group(s) being deleted.")]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $GroupNames,

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    )
    # Check whether group exists, if it does not create new group, set path and attach policy
    $AllRemovedIAMGroups = @()
    foreach ($GroupName in $($GroupNames -split ","))
    {
        $GroupExist = Get-IAMGroups -ProfileName $ProfileName | where {$_.GroupName -eq $GroupName }

        if ($GroupExist)
        {
            $GroupPolicies = Get-IAMGroupPolicies -ProfileName $ProfileName -GroupName $GroupName
            $AllGroupPolicies = @()

            if ($GroupPolicies)
            {
                foreach ($GroupPolicy in $GroupPolicies)
                {
                    write-verbose "Policy Name:$GroupPolicy "
                    Try
                    {
                        Remove-IAMGroupPolicy -GroupName $GroupName -PolicyName $GroupPolicy -Force
                        write-verbose "Removed IAM Group Policy: $GroupPolicy"
                        $AllGroupPolicies += $GroupPolicy
                    }

                    Catch
                    {
                        $Host.UI.WriteErrorLine("`nUnable to delete IAM Group Policy: $GroupPolicy.`n$_.error`n")
                        $AllGroupPolicies += "Error: $_.error"
                    }
                }
            }
            
            else 
            {
                write-verbose "No IAM Group Policy:"
                $AllGroupPolicies = 'NONE'                
            }

            Try
            {
                Remove-IAMGroup -GroupName $GroupName -Force
                write-verbose "Removed IAM Group: $GroupName"
                $GroupDeleted = $TRUE
            }

            Catch
            {
                $Host.UI.WriteErrorLine("`nUnable to delete IAM Group: $Groupname.`n$_.error`n")
                $GroupDeleted = 'ERROR: $_.error'
            }  
        }

        else 
        {
            $GroupDeleted = 'GROUP NOT FOUND'
            $AllGroupPolicies = 'GROUP NOT FOUND'
            write-verbose "Group: $GroupName not found "
        }

        # Return AWS account number
        $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
        $AccountNumber = $Matches[0] 

        # Add all information to PS Object
        $RemovedIAMGroupInfo = [ordered] @{
                                AWSAccountNumber="$AccountNumber";
                                AWSAccountName="$ProfileName";
                                GroupName="$Groupname";
                                GroupPolicyDeleted="$AllGroupPolicies";
                                GroupDeleted="$GroupDeleted"                           
                            }

        $RemovedIAMGroupObj = New-Object -Type PSObject -Prop $RemovedIAMGroupInfo
        $AllRemovedIAMGroups += $RemovedIAMGroupObj
    }

    $AllRemovedIAMGroups
}
<#
.SYNOPSIS
    Adds a security group ingress rule.
.DESCRIPTION
    Adds an ingress rule for an EC2 or VPC security group  on port, protocol
.PARAMETER SecurityGroupName
    The name of the security group you want to add the ingress rule(s) to. If you are adding a rule for a VPC group you must include the VPCID.
.PARAMETER VPCID
    The VPC ID, if the group is in a VPC and not EC2 classic.
.PARAMETER SecurityGroupID
    The ID of the security group you want to add the ingress rule(s) to.
.PARAMETER Region
    The AWS region to check for empty security groups (from: us-east-1,us-west-1,us-west-2,eu-west-1,'eu-central-1,ap-northeast-1,ap-southeast-1,ap-southeast-2,sa-east-1)
.PARAMETER SourceIPs
    Enter the list of source IPs (including CIDR notation e.g 132.188.32.0/24) you want to add as the source for the ingress rule. If you do not include a CIDR notation it will be set to /32"   
.PARAMETER SourceGroupID
    The ID of the security group you want to add as the source for the ingress rule. If the group is in a different AWS account you must include the account number in the following format: AccountNumber/SourceGroupID"
.PARAMETER MyCurrentIP
    If the switch MyCurrentIP is set, your current IP address is returned and set as the source IP.
.PARAMETER AddQualys
    If the switch AddQualys is set, ingress rules are added to allow all tcp/udp/icmp traffic from the region specific Qualys group.
.PARAMETER IngressRules
    Enter the rules(s) that you want added to the ingress rule. You can enter a comma seperated list of rules using the following syntax:
    PortNumber -                Adds a TCP ingress rule for a single port (e.g 443 adds a rule for TCP port 443(HTTPS))
    PortNumber-PortNumber -     Adds a TCP ingress rule for a range of ports (e.g 27017-27019 adds a rule for TCP ports
                                27017, 27018, 27019 (MongoDB))
    UDP:PortNumber              Adds a UDP ingress rule for a single port (e.g UDP:53 adds a rule for UDP port 53(DNS))
    UDP:PortNumber-PortNumber   Adds a UDP ingress rule for a range of ports (e.g UDP:20-25 adds a rule for UDP ports
                                20,21,22,23,24,25) 
    ICMP                        Adds an ICMP ingress rule to allow all ICMP traffic.
    TCP                         Adds a TCP ingress rule allowing all ports (0-65535)
    UDP                         Adds a UDP ingress rule allowing all ports (0-65535)
    ALL                         Adds ingress rules for TCP/UDP/ICMP allowing all ports (0-65535)
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns $NewPasswordPolicy which is an array of PS objects containing the following information:
.NOTES
    NAME......:  Add-AWSIngressRule
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  1/15/15
.EXAMPLE
    Add-AWSIngressRule -SecurityGroupName 'MyEC2Group' -Region 'us-east-1' -SourceIP's '115.112.233.64/32' -IngressRules '22,3389'
    Adds an ingressrule to EC2SecurityGroup named 'MyEC2Group' in in AWS region 'us-east-1'. The rule allows TCP ports 22 and 3389 from source IP 115.112.233.64/26
.EXAMPLE
    Add-AWSIngressRule -SecurityGroupName 'MyEC2Group' -Region 'us-east-1' -SourceIP's '115.112.233.64/26' -IngressRules '27017-27019'
    Adds an ingressrule to EC2SecurityGroup named 'MyEC2Group' in AWS region 'us-east-1'. The rule allows TCP ports 27017-27019 from source IPs 115.112.233.64/26
.EXAMPLE
    Add-AWSIngressRule -SecurityGroupName 'MyEC2Group' -Region 'us-west-2' -SourceIPs '115.112.233.64/26' -IngressRules '27017-27019,UDP:53'
    Adds an ingressrule to EC2SecurityGroup named 'MyEC2Group' in AWS region 'us-west-2'. The rule allows TCP ports 27017-27019 and UDP port 53 from source IPs 115.112.233.64/26.
.EXAMPLE
    Add-AWSIngressRule -SecurityGroupName 'MyEC2Group' -Region 'us-west-1' -SourceGroupID '1234567890\sg-abcde123' -IngressRules 'ICMP'
    Adds an ingressrule to EC2SecurityGroup named 'MyEC2Group' in AWS region 'us-west-1'. The rule allows all ICMP ports from source group sg-abcde123 in AWS account 1234567890.
.EXAMPLE
    Add-AWSIngressRule -SecurityGroupName 'MyEC2Group' -Region 'us-west-1' -SourceGroupID '1234567890\sg-abcde123' -IngressRules 'ICMP'
    Adds an ingressrule to EC2SecurityGroup named 'MyEC2Group' in AWS region 'us-west-1'. The rule allows all ICMP ports from source group sg-abcde123 in AWS account 1234567890.
#>
function Add-AWSIngressRule
{
    [CmdletBinding()] 
    Param (
        [Parameter(Mandatory=$false,HelpMessage="Enter the name of the security group you want to add the ingress rule(s) to.")]
        [ValidateNotNullOrEmpty()]
        [String]
        $SecurityGroupName,

        [Parameter(Mandatory=$false,HelpMessage="Enter the ID of the security group you want to add the ingress rule to.")]
        [ValidateNotNullOrEmpty()]
        [String]
        $SecurityGroupID,

        [Parameter(Mandatory=$false,HelpMessage="Enter the VPC ID, if the group is in a VPC and not EC2 classic.")]
        [ValidateNotNullOrEmpty()]
        [String]
        $VPCID,

        [Parameter(Mandatory=$false,HelpMessage="Enter the name of AWS region that the security group resides in (from: us-east-1,us-west-1,us-west-2,eu-west-1,'eu-central-1,ap-northeast-1,ap-southeast-1,ap-southeast-2,sa-east-1)")]
        [ValidateSet("us-east-1","us-west-1","us-west-2","eu-west-1","eu-central-1","ap-northeast-1","ap-southeast-1","ap-southeast-2","sa-east-1")] 
        [String]
        $Region,

        [Parameter(Mandatory=$false,HelpMessage="Enter the list of source IPs (including CIDR notation e.g 132.188.32.0/24) you want to add as the source for the ingress rule. If you do not include a CIDR notation it will be set to /32")] 
        [String]
        $SourceIPs,

        [Parameter(Mandatory=$false,HelpMessage="Enter the ID of the security group you want to add as the source for the ingress rule. If the group is in a different AWS account you must include the account number in the following format: AccountNumber/SourceGroupID")] 
        [String]
        $SourceGroupID,

        [Parameter(Mandatory=$false,HelpMessage="If the switch MyCurrentIP is set, your current IP address is returned and set as the source.")] 
        [Switch]
        $MyCurrentIP,

        [Parameter(Mandatory=$false,HelpMessage="If the switch AddQualys is set, ingress rules are added to allow all tcp/udp/icmp traffic from the region specific Qualys group.")] 
        [Switch]
        $AddQualys,

        [Parameter(Mandatory=$false,HelpMessage="Enter the rules(s) that you want added to the ingress rule. You can enter a comma seperated list of rules using the following logic:
            Port - Adds TCP ingress rule for a single port (e.g 443 adds a rule for TCP port 443 (HTTPS))
            Port-Port - Adds a TCP ingress rule for a range of ports (e.g 27017-27019 adds a rule for TCP ports 27017, 27018, 27019 (MongoDB))
            UDP:PortNumber - Adds a UDP ingress rule for a single port (e.g UDP:53 adds a rule for UDP port 53 (DNS)).
            UDP:Port-Port - Adds a UDP ingress rule for a range of ports (e.g UDP:20-25 adds a rule for UDP ports 20,21,22,23,24,25) 
            ICMP - Adds an ICMP ingress rule to allow all ICMP traffic.
            TCP - Adds a TCP ingress rule allowing all ports (0-65535)
            UDP - Adds a UDP ingress rule allowing all ports (0-65535)
            ALL - Adds ingress rules for TCP/UDP/ICMP allowing all ports (0-65535)
            ")] 
        [string]
        $IngressRules,

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    )
    write-verbose $IngressRules

    # Validate that the input paramaters are valid    
    if (!($SecurityGroupName -or $SecurityGroupID))
    {
        $Host.UI.WriteErrorLine("`nYou must enter the name or ID security group you want to add the ingress rule to.`n$_.error`n")
        Return
    }

    if (!($SourceIPs -or $SourceGroupID -or $SourceGroupName -or $MyCurrentIP -or $AddQualys))
    {
        $Host.UI.WriteErrorLine("`nYou must enter the IPs or a security group name or ID that is the source for ingress rule you want to add.`n")
        Return
    }

    if (!($IngressRules -or $AddQualys))
    {
        $Host.UI.WriteErrorLine("`nYou must specifiy INgress rules to add or use the AddQualys switch.`n")
        Return
    }    

    if ($AddQualys)
    {
        if ($Region -eq 'us-east-1')
        {
            $SourceGroupID= '040799898422\sg-ffdfa194'
        }

        elseif ($Region -eq 'us-west-1')
        {
            $SourceGroupID = '040799898422\sg-22cb7766'
        }

        elseif ($Region -eq 'us-west-2')
        {
            $SourceGroupID = '040799898422\sg-56768b65'
        }

        else 
        {
            $Host.UI.WriteErrorLine("`nThere is no Qualys group for this region: $Region`n")
            Return              
        }

        $IngressRules = 'tcp,udp,icmp'
    }  

    # Validate that the security group exists and return PS object with group information.
    if ($SecurityGroupName)
    {
        if ($VPCID)
        {
            Try
            {
                $SecurityGroupID = ((Get-EC2SecurityGroup -region $Region -ProfileName $ProfileName) | where { $_.GroupName -eq $SecurityGroupName -and $_.VPCID -eq $VPCID }).GroupID
                write-verbose "Found security group to add ingress rule to, GroupID: $SecurityGroupID GroupName: $SecurityGroupName"
            }            

            catch 
            {
                $Host.UI.WriteErrorLine("`nUnable to locate VPC security group name: $SecurityGroupName in VPC $VPCID.`n$_.error`n")
                Break                
            }
        }

        else 
        {
            Try
            {
                $SecurityGroupID = ((Get-EC2SecurityGroup -region $Region -ProfileName $ProfileName) | where { $_.GroupName -eq $SecurityGroupName }).GroupID
                $VPCID = $False
                write-verbose "Found EC2 security group to add ingress rule to, GroupID: $SecurityGroupID GroupName: $SecurityGroupName"
            }            

            catch 
            {
                $Host.UI.WriteErrorLine("`nUnable to locate security group name: $SecurityGroupName.`n$_.error`n")
                Return                
            }
        }
    }

    elseif ($SecurityGroupID)
    {
        Try
        {
            $SecurityGroupName  = ((Get-EC2SecurityGroup -region $Region -ProfileName $ProfileName) | where { $_.GroupID -eq $SecurityGroupID }).GroupName            
            write-verbose "Found security group to add ingress rule to, GroupID: $SecurityGroupID GroupName: $SecurityGroupName"
        }            

        catch 
        {
            $Host.UI.WriteErrorLine("`nUnable to locate security group with ID: $SecurityGroupID in VPC: $VPCID.`n$_.error`n")
            Return                
        } 
    }

    # Retrieve current IP address from whatismyipaddress API, add CIDR notation and set as SourceIP
    if ($MyCurrentIP)
    {
        Try
        {
            $CurrentIP = Invoke-RestMethod http://bot.whatismyipaddress.com
            $SourceIPs = $CurrentIP + "/32"
            write-verbose "Adding current IP: $SourceIPs"
        }

        Catch
        {
            $Host.UI.WriteErrorLine("`nThere is an issue retrieving your current IP address.`n$_.error `n")
            Return                
        }
    } 

    # If 'ALL' is specified set rules as all tcp,udp and icmp
    if ($IngressRules -like '*all*')
    {
        $IngressRules = 'tcp,udp,icmp'
    }

    # Evaluate each rule from the input parameter
    $IngressRuleObj = @()
    $IngressGroupRuleObj = @()
    $NewIngressRules = @()
    
    foreach ($IngressRule in $IngressRules.split(',').trim())
    {
        write-host ""
        write-verbose "Ingress Rule: $IngressRule"

        if ($IngressRule -match "^(6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}|0)$")
        {
            write-verbose "TCP port rule"  
            $FromPort = $IngressRule
            $ToPort = $IngressRule
            $Protocols = 'tcp'
        }

        elseif ($IngressRule -like '*-*' -and $IngressRule -notlike 'udp:*')
        {
            write-verbose "TCP port range"
            $FromPort = $IngressRule.split('-')[0]
            $ToPort = $IngressRule.split('-')[1]
            $Protocols = 'tcp'  
        }

        elseif ($IngressRule -eq 'tcp')
        {
            write-verbose "TCP all ports"
            $FromPort = 0
            $ToPort = 65535
            $Protocols = 'tcp'
        }

        elseif ($IngressRule -like 'udp:*' -and $IngressRule -notlike 'udp:*-*')
        {  
            write-verbose "UDP port rule"  
            $FromPort = $IngressRule.split(':')[1]
            $ToPort = $IngressRule.split(':')[1]
            $Protocols = 'udp'
        }      

        elseif ($IngressRule -like 'udp:*-*')
        {
            write-verbose "UDP port range"
            $SplitRule = $IngressRule.split(':')[1]
            $FromPort = $SplitRule.split('-')[0]
            $ToPort = $SplitRule.split('-')[1]
            $Protocols = 'udp'
        }

        elseif ($IngressRule -eq 'udp')
        {
            write-verbose "UDP all ports"
            $FromPort = 0
            $ToPort = 65535
            $Protocols = 'udp'
        }

        elseif ($IngressRule -eq 'icmp')
        {
            write-verbose "ICMP all ports"
            $FromPort = -1
            $ToPort = -1
            $Protocols = 'icmp'
        }

        elseif ($IngressRule -eq 'all')
        {
            write-verbose "TCP/UDP/ICMP all ports"
            $FromPort = 0
            $ToPort = 65535
            $Protocols = 'tcp,udp,icmp'
        }

        else 
        {
            $Host.UI.WriteErrorLine("`nUnable to add Ingress Rule has bad syntax: $IngressRule`n")
            break
        }

        foreach ($Protocol in $Protocols.split(',').trim().tolower())
        {
            if ($Protocol -eq 'icmp')
            {
                $FromPort = '-1'
                $ToPort = '-1'            
            }

            if ($SourceIPs)
            {
                $Source = @()

                foreach ($SourceIP in $SourceIPs.split(',').trim())
                {            
                    if($SourceIP -like '*/*') 
                    {
                        $IPSplit = $SourceIP.split("/")
                        $IP = $IPSplit[0]
                        $CIDR = $IPSplit[1]
                        write-verbose "Split: $IP CIDR: $CIDR"
                    }

                    else 
                    {
                        $IP = $SourceIP
                        $CIDR = '32'
                        write-verbose "No CIDR: $IP Adding /32"
                    }

                    if ([bool]($IP -as [ipaddress]) -eq $True)
                    {
                        $ValidIP = $IP + '/' + $Mask
                        write-verbose "$ValidIP is a Valid IP"
                    }
                    else 
                    {
                        $Host.UI.WriteErrorLine("`nUnable to add Ingress rule, source IP is not valid: $SourceIP`n")
                    }

                    write-verbose "Creating ingress rule source IP: $SourceIP"
                    $NewIngressRule = New-Object Amazon.EC2.Model.IpPermission
                    $NewIngressRule.IpProtocol = $Protocol
                    $NewIngressRule.FromPort = $FromPort
                    $NewIngressRule.ToPort = $ToPort
                    $NewIngressRule.IpRanges.Add("$SourceIP")
                    
                    Try
                    {
                        Grant-EC2SecurityGroupIngress -GroupID $SecurityGroupID -IpPermissions $NewIngressRule -region $Region -ProfileName $ProfileName
                        $Source += $SourceIP -join(", ")
                    }

                    Catch 
                    {
                        $Host.UI.WriteErrorLine("`nUnable to add Ingress rule to: $SecurityGroupName for Source IP: $SourceIP. $_.error `n")
                        break                        
                    }
                }                
            }

            elseif ($SourceGroupID)
            {
                write-verbose "Creating ingress rule source group ID: $SourceGroupID"
                $SourceGroupSplit = $SourceGroupID.split('\').trim()
                $GroupPairAccountNumber = $SourceGroupSplit[0] 
                $GroupPairID = $SourceGroupSplit[1]

                $NewIngressRule = New-Object Amazon.EC2.Model.IpPermission
                $NewIngressRule.IpProtocol = $Protocol
                $NewIngressRule.FromPort = $FromPort
                $NewIngressRule.ToPort = $ToPort
                $UserGroupPair = New-Object Amazon.EC2.Model.UserIdGroupPair
                $UserGroupPair.GroupId = $GroupPairID
                $UserGroupPair.UserId = $GroupPairAccountNumber
                $NewIngressRule.UserIdGroupPairs.Add($UserGroupPair)
                $Source = $SourceGroupID
                
                Try
                {
                    Grant-EC2SecurityGroupIngress -GroupID $SecurityGroupID -IpPermissions $NewIngressRule -region $Region -ProfileName $ProfileName
                }

                Catch 
                {
                    $Host.UI.WriteErrorLine("`nUnable to add Ingress rule to $SecurityGroupID for Source Group ID: $SourceIP. $_.error `n")
                    break                        
                }
            } 

            $NewIngressRuleInfo = [ordered]  @{
                                AWSAccountNumber="$AccountNumber";
                                AWSAccountName="$ProfileName";
                                SecurityGroupName="$SecurityGroupName";
                                SecurityGroupID="$SecurityGroupName";
                                VPCID="$VPCID";
                                Source="$Source";
                                Protocol="$Protocol";
                                FromPort="$FromPort";
                                ToPort="$ToPort"
                            }  
            $NewIngressRuleObj = New-Object -Type PSObject -Prop $NewIngressRuleInfo
            $NewIngressRules += $NewIngressRuleObj
        }        
    }
    
    $NewIngressRules
}
<#
.SYNOPSIS
    Adds a security group ingress rule.
.DESCRIPTION
    Adds an ingress rule for an EC2 or VPC security group  on port, protocol
.PARAMETER Region
    The AWS region to check for empty security groups (from: us-east-1,us-west-1,us-west-2,eu-west-1,'eu-central-1,ap-northeast-1,ap-southeast-1,ap-southeast-2,sa-east-1)
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
#>
function Get-AWSIngressRules
{
    [CmdletBinding()] 
    Param (
        [Parameter(Mandatory=$false,HelpMessage="Enter the name of AWS region that the security group resides in (from: us-east-1,us-west-1,us-west-2,eu-west-1,'eu-central-1,ap-northeast-1,ap-southeast-1,ap-southeast-2,sa-east-1)")]
        [ValidateSet("us-east-1","us-west-1","us-west-2","eu-west-1","eu-central-1","ap-northeast-1","ap-southeast-1","ap-southeast-2","sa-east-1")] 
        [String]
        $Region,

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [String]
        $ProfileName
    )

    $Groups = Get-EC2SecurityGroup -region $region -ProfileName $ProfileName 
    $AllSecurityGroups = @() 
    
    foreach ($Group in $Groups)
    {        
        $AllInstancesinGroup = @()
        $AllELBsinGroup = @()

        $SecurityGroupName = $Group.GroupName
        $SecurityGroupId = $Group.GroupID
        $SecurityGroupDescription = $Group.Description
        $SecurityGroupVPCID = $Group.VPCID

        $InstancesinGroups = ((get-ec2instance -region $region -ProfileName $ProfileName).instances | where { $($_.securitygroups).GroupName -eq $SecurityGroupName } )
        $ELBsinGroup = (Get-ELBLoadBalancer -region $region -ProfileName $ProfileName) | where { $_.SecurityGroups -eq $SecurityGroupId}
        $RDSGroup = (Get-RDSDBInstance -region $region -ProfileName $ProfileName) | where { $_.VpcSecurityGroups -eq $SecurityGroupId}

        if ($InstancesinGroups)
        {
            foreach ($InstancesinGroup in $InstancesinGroups)
            {
                $InstanceID = $InstancesinGroup.InstanceID
                $AllInstancesinGroup += $InstanceID
            }
            $NumberInstances = $($InstancesinGroups.count)
        }

        else 
        {
            $AllInstancesinGroup = 'NONE'
            $NumberInstances = 0
        }

        if ($ELBsinGroup)
        {
            foreach ($ELBinGroup in $ELBsinGroup)
            {
                $LoadBalancerName = $ELBinGroup.LoadBalancerName
                $AllELBsinGroup += $LoadBalancerName -join (",")
            }
        }

        else 
        {
            $AllELBsinGroup = 'NONE'
        }

        
        if (!($RDSGroups))
        {
            $RDSGroups = 'NONE'
        }

        if (!($SecurityGroupVPCID))
        {
            $SecurityGroupVPCID = 'N/A'
        }

        foreach ($Ingressrule in $($Group.IpPermissions) )
        {
            $Protocol = $Ingressrule.IpProtocol
            $FromPort = $Ingressrule.FromPort
            $ToPort = $Ingressrule.ToPort

            $AllSourceIPs = @()
            $AllSourceGroups = @()

            if ($Ingressrule.IPRanges)
            {
                $SourceIPs = $Ingressrule.IPRanges

                foreach ($SourceIP in $SourceIPs)
                {
                    $AllSourceIPs += $SourceIP 

                    if ($SourceIP -eq '0.0.0.0/0')
                    {
                        $OpenGroup = $True
                    }

                    else 
                    {
                        $OpenGroup = $False
                    }
                }
            }

            else 
            {
                $AllSourceIPs = 'NONE'
            }

            if ($Ingressrule.UserIdGroupPairs)
            {
                foreach ($SourceGroup in $Ingressrule.UserIdGroupPairs)
                { 
                    $SourceGroupName = $SourceGroup.GroupName
                    $SourceGroupID = $SourceGroup.GroupID
                    $SourceGroupInfo = $SourceGroupID + "($SourceGroupName)"
                    $AllSourceGroups += $SourceGroupInfo
                }
            }

            else 
            {
                $AllSourceGroups = 'NONE'
            }

            # Return AWS account number from account
            $RegexAccountNumber = $((Get-IAMUser -ProfileName $ProfileName).arn) -match "(\d+)" | Out-Null; 
            $AccountNumber = $Matches[0]

            $SecurityGroupInfo = [ordered]  @{
                                AWSAccountNumber="$AccountNumber";
                                AWSAccountName="$ProfileName";
                                SecurityGroupName="$SecurityGroupName";
                                SecurityGroupID="$SecurityGroupID";
                                VPCID="$($Group.VPCID)";
                                Protocol="$Protocol";
                                FromPort="$FromPort";
                                ToPort="$ToPort";
                                SourceGroups="$($AllSourceGroups -join(","))";
                                SourceIPs="$($AllSourceIPs -join(","))";
                                OpenGroup="$OpenGroup";
                                InstancesinGroup="$($AllInstancesinGroup -join(","))";
                                NumberInstances="$NumberInstances";
                                ELBsInGroup="$AllELBsinGroup";
                                RDSGroups="$RDSGroups"
                            }

            $SecurityGroupObj = New-Object -Type PSObject -Prop $SecurityGroupInfo
            $AllSecurityGroups += $SecurityGroupObj
        }
    }
}
<#
.SYNOPSIS
    Imports AWS credentials and creates profiles.
.DESCRIPTION
    Imports AWS credentials and creates profiles from a .csv file 
.PARAMETER Path
    The path to the .csv file containing the credentials you want to import. The .csv file should have the following columns PSAlias,Key and Secret.
.OUTPUTS
    Returns $NewPSProfileInfo which is a PS object containing the following information:
    AWSAccountNumber:       The AWS account number that contains the IAM user.
    AWSAccountName:         The AWS account name that contains the IAM user.
    ProfileCreated:         Whether the PS profile was created sucessfully
.NOTES
    NAME......:  Import-AWSProfiles
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  1/30/15
.EXAMPLE
    Import-AWSProfiles -Path 'C:\MyProfiles.csv'
    Imports a list of PS profiles from the .csv file 'MyProfiles'
#>
function Import-AWSProfiles
{
    [CmdletBinding()]
    Param ( 
        [Parameter(Mandatory=$true,HelpMessage="Enter the path to the .csv file containing the AWS profile information you want to import.")]
        [ValidateScript({Test-Path $_ })]
        [string[]]
        $Path  
    )

    $AWSProfiles = Import-Csv $Path
    $AllPSProfiles = @()
    write-verbose "Creating powershell profiles from: $Path"

    foreach ($AWSProfile in $AWSProfiles) 
    {
        Set-AWSCredentials -AccessKey $($AWSProfile.AccessKey) -SecretKey $($AWSProfile.SecretKey) -StoreAs $($AWSProfile.PSAlias)            
        Try
        {
            $RegexAccountNumber = $((Get-IAMUser -ProfileName $($AWSProfile.PSAlias)).arn) -match "(\d+)" | Out-Null; 
            $AccountNumber = $Matches[0] 
            $ProfileCreated = 'SUCESS'
            write-verbose "Powershell profile: $($AWSProfile.PSAlias) Set"
        }

        Catch
        {
            $Host.UI.WriteErrorLine("`nUnable to create new profile: $($AWSProfile.PSAlias)`n$_.error`n")
            $AccountNumber = 'N/A'
            $ProfileCreated = 'FAILED'
        }        

        $NewPSProfileInfo = [ordered] @{
                        AWSAccountNumber="$AccountNumber";
                        AWSAccountName="$($AWSProfile.PSAlias)";
                        ProfileCreated="$ProfileCreated"
                        }

        $NewPSProfileObj = New-Object -Type PSObject -Prop $NewPSProfileInfo
        $AllPSProfiles += $NewPSProfileObj
    }

    $AllPSProfiles
}
<#
.SYNOPSIS
    Removes permissions for existing AMIs.
.DESCRIPTION
    Based on the input of an AMI-ID or AMI-Name and AWS region will search other AWS regions for the AMI and then revoke all permissions from the AMI, unsharing it from other accounts. 
.PARAMETER AMIID
    The ID of the AMI that you want to remove permissions from.
.PARAMETER AMIName
    Enter the Name of the AMI that you want to revoke permissions from.
.PARAMETER Region
    The AWS region to check for empty security groups. 
.PARAMETER ProfileName
    The name of the AWS profile to use for the operation.
.OUTPUTS
    Returns an array $RemovedPermissionImages which is an array of PS objects containing information about each AMI:
    AMIID:                  The ID of the AMI that you want to remove permissions for.
    Region:                 The AWS region that the AMI is located in.  
    Name:                   The name of the AMI based on OS and Date.
.NOTES
    NAME......:  Revoke-AMIPermissions.ps1
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  1/5/15
.EXAMPLE
    Revoke-AMIPermissions -SourceRegion 'us-east-1' -AMIName 'Hardened_WINDOWS_2008_BASE_06262014' -ProfileName 'PRODUCTION_SPS_AMI' -verbose
    Finds the ID of the AMI 'Hardened_WINDOWS_2008_BASE_06262014' in AWS region 'us-east-1' and searches all other regions in the AWS account 'PRODUCTION_SPS_AMI' for any AMI's that match the name. If a match is found, all permissions (the list of other accounts the AMI has been shared with) are removed.
.EXAMPLE
    Revoke-AMIPermissions -SR 'us-east-1' -ID 'Hardened_WINDOWS_2008_BASE_06262014' -P 'PRODUCTION_SPS_AMI' -verbose

    Finds the ID of the AMI 'Hardened_WINDOWS_2008_BASE_06262014' in AWS region 'us-east-1' and searches all other regions in the AWS account 'PRODUCTION_SPS_AMI' for any AMI's that match the name. If a match is found, all permissions (the list of other accounts the AMI has been shared with) are removed.
#>
function Revoke-AMIPermissions
{
    [CmdletBinding()] 
    Param (
        [Parameter(Mandatory=$true,HelpMessage="Enter the name of AWS region that the AMI that you want to revoke permissions for resides in.")]
        [ValidateSet("us-east-1","us-west-1","us-west-2","eu-west-1","eu-central-1","ap-northeast-1","ap-southeast-1","ap-southeast-2","sa-east-1")] 
        [alias('SR')]
        [String]
        $SourceRegion,

        [Parameter(Mandatory=$false,HelpMessage="Enter the ID of the AMI that you want to revoke permissions from.")]
        [alias('ID')]
        [string]
        $AMIID,

        [Parameter(Mandatory=$false,HelpMessage="Enter the Name of the AMI that you want to revoke permissions from.")]
        [alias('N')]
        [string]
        $AMIName,        

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the AWS profile to use for the operation.")]
        [alias('P')]
        [String]
        $ProfileName
    )

    $RemovedPermissionImages = @()

    if (!($AMIID -or $AMIName))
    {
        $Host.UI.WriteErrorLine("You must enter the AMI name or ID for the image you want to revoke permissions for`n")      
    }

    if ($AMIID)
    {
        $AMIName = (Get-EC2Image -ImageID $AMIID -ProfileName $ProfileName).name
        write-verbose "Image name: $AMIName ID: ($AMIID)"
    }

    elseif ($AMIName)
    {
        $AMIID = (Get-EC2Image -owner self -ProfileName $ProfileName | where {$_.name -eq $AMIName}).ImageId
        write-verbose "Image name: $AMIName ID: ($AMIID)"
    }

    if (!($AMIID -and $AMIName))
    {
        $Host.UI.WriteErrorLine("Unable to find image name: $AMIName and ID: $AMIID`n")
        Break   
    }

    $Regions = (Get-EC2Region).regionname

    foreach ($Region in $Regions)
    {
        $RegionAMIs = (get-ec2image -owner self -region $Region -ProfileName $ProfileName) | where { $_.name -eq $AMIName }

        if ($RegionAMIs)
        {
            foreach ($RegionAMI in $RegionAMIs)
            {
                $RegionAMIID = $($regionAMI).ImageID
                
                write-verbose "Found AMIID: $RegionAMIID ($AMIName) in region: $Region"

                $AMIPermissions = (Get-EC2ImageAttribute -ImageId $RegionAMIID -Attribute "launchPermission" -region $Region -ProfileName $ProfileName | select -expand Launchpermissions).userid
           
                if ($AMIPermissions)
                {
                    write-verbose "AMIID: $RegionAMIID ($AMIName) has been shared with other accounts, removing permissions.`n" 
                    
                    foreach ($AMIPermission in $AMIPermissions)
                    {
                        write-verbose "Removing permission AWS Account $AMIPermission for AMIID: $RegionAMIID ($AMIName)"
                        Edit-EC2ImageAttribute -ImageId $regionAMIID -Attribute "launchPermission" -OperationType "remove" -UserId $AMIPermission -region $Region -ProfileName $ProfileName
                    }

                    $AMIInfo = [ordered]  @{
                                SourceAMIID="$AMIID";
                                SourceAMIName="$AMIName";
                                Region="$Region";
                                RegionAMIID="$RegionAMIID";
                            }

                    $AMIObj = New-Object -Type PSObject -Prop $AMIInfo   
                    $RemovedPermissionImages += $AMIObj  
                }

                else 
                {
                    write-verbose "The AMI ($AMIName) has not been shared to any accounts."
                }
            }
        }

        else 
        {
           write-verbose "No AMI found in region: $Region."
        }
    }

    $RemovedPermissionImages
}
