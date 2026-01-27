rule HackTool_Win64_DefControl_DA_2147961272_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/DefControl.DA!MTB"
        threat_id = "2147961272"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "DefControl"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "github.com/lkarlslund/defender-acl-blocker" ascii //weight: 10
        $x_1_2 = "Go build ID:" ascii //weight: 1
        $x_1_3 = "crypto/internal/fips140/aes.encryptBlock" ascii //weight: 1
        $x_1_4 = "crypto/internal/fips140/aes.decryptBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_DefControl_A_2147961762_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/DefControl.A"
        threat_id = "2147961762"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "DefControl"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "go-winio.enableDisableProcessPrivilege" ascii //weight: 2
        $x_1_2 = "impersonate SYSTEM:" ascii //weight: 1
        $x_1_3 = "impersonate TRUSTEDINSTALLER:" ascii //weight: 1
        $x_2_4 = "main.TRUSTEDINSTALLER" ascii //weight: 2
        $x_2_5 = "main.impersonate" ascii //weight: 2
        $x_2_6 = "/x/sys/windows.ACLFromEntries" ascii //weight: 2
        $x_1_7 = "Error extracting DACL: %v" ascii //weight: 1
        $x_1_8 = "cannot create new ACL:" ascii //weight: 1
        $x_1_9 = "Remove all DENY ACLs from" ascii //weight: 1
        $x_1_10 = "WinDefendMDCoreSvc" ascii //weight: 1
        $x_1_11 = "mpssvcwscsvc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

