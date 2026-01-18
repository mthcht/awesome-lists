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

