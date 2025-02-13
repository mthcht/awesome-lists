rule Trojan_Win32_DelShad_SK_2147759873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelShad.SK!MTB"
        threat_id = "2147759873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelShad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /f /im lsass.exe" ascii //weight: 1
        $x_1_2 = "shutdown /r /t 150 /c \"trolololololololol\"" ascii //weight: 1
        $x_1_3 = "Congratulations.txt" ascii //weight: 1
        $x_1_4 = "excuse me mate you installed malware on the system" ascii //weight: 1
        $x_1_5 = "Yeah Yeah its 420 time" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_DelShad_DAX_2147888509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelShad.DAX!MTB"
        threat_id = "2147888509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelShad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bc 80 b3 18 e1 5c 80 f9 21 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 43 6c 61 73}  //weight: 1, accuracy: High
        $x_1_2 = {6b 82 4f bd 52 33 63 b2 af 49 91 3a 4f ad 33 99 66 cf 11 b7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

