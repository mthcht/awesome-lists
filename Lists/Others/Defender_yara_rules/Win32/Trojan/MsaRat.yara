rule Trojan_Win32_MsaRat_BA_2147974870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MsaRat.BA!MTB"
        threat_id = "2147974870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MsaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msaMessage(base64Data)" ascii //weight: 1
        $x_1_2 = "msaError" ascii //weight: 1
        $x_1_3 = "msaOpen" ascii //weight: 1
        $x_1_4 = "msaClose" ascii //weight: 1
        $x_1_5 = "msa.send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

