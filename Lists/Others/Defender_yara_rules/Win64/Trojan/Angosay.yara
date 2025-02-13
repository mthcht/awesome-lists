rule Trojan_Win64_Angosay_C_2147725779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Angosay.C!dll"
        threat_id = "2147725779"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Angosay"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\ExtractedBundle\\RTM_ImageModRec_1.1.5.0_x64\\RTM_ImageModRec.pdb" ascii //weight: 1
        $x_1_2 = "ResolveLocaleName" ascii //weight: 1
        $x_1_3 = "IsValidLocaleName" ascii //weight: 1
        $x_1_4 = "RhpCopyAnyWithWriteBarrier" ascii //weight: 1
        $x_1_5 = "RhpCheckedLockCmpXchg" ascii //weight: 1
        $x_1_6 = "RhpAssignRefEDX" ascii //weight: 1
        $x_1_7 = "ReadFile" ascii //weight: 1
        $x_1_8 = "WriteFile" ascii //weight: 1
        $x_1_9 = "FindClose" ascii //weight: 1
        $x_1_10 = "GetFileType" ascii //weight: 1
        $x_1_11 = "SetEndOfFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Angosay_D_2147725806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Angosay.D!dll"
        threat_id = "2147725806"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Angosay"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VPJqkd2Sn0uPSmU5BM8Lwg\\ExtractedBundle\\RTM_ImageModRec_1.1.5.0_x64\\RTM_ImageModRec.pdb" ascii //weight: 1
        $x_1_2 = "VPJqkd2Sn0uPSmU5BM8Lwg\\ExtractedBundle\\RTM_ImageModRec_1.1.5.0_x64\\RTM_ImageModRec.pdb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Angosay_E_2147725807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Angosay.E!dll"
        threat_id = "2147725807"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Angosay"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VPJqkd2Sn0uPSmU5BM8Lwg\\ExtractedBundle\\RTM_ImageModRec_1.1.5.0_x64\\RTM_ImageModRec.pdb" ascii //weight: 1
        $x_1_2 = "VPJqkd2Sn0uPSmU5BM8Lwg\\ExtractedBundle\\RTM_ImageModRec_1.1.5.0_x64\\RTM_ImageModRec.pdb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

