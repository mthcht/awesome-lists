rule VirTool_Win64_MeterIncognito_A_2147967405_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/MeterIncognito.A"
        threat_id = "2147967405"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MeterIncognito"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "No tokens available" ascii //weight: 1
        $x_1_2 = "[+] Successfully impersonated user" ascii //weight: 1
        $x_1_3 = "[-] User token" ascii //weight: 1
        $x_1_4 = "SeImpersonatePrivilege" ascii //weight: 1
        $x_1_5 = "[+] Successfully added user to group" ascii //weight: 1
        $x_1_6 = "[-] Operation only allowed on primary domain controller" ascii //weight: 1
        $x_1_7 = "[-] Password does not meet complexity requirements" ascii //weight: 1
        $x_1_8 = "[+] Successfully added user" ascii //weight: 1
        $x_1_9 = "[-] Special group" ascii //weight: 1
        $x_1_10 = "[+] Successfully added user to local group" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

