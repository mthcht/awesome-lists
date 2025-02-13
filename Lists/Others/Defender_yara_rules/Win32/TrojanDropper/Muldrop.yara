rule TrojanDropper_Win32_Muldrop_C_2147607468_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Muldrop.C"
        threat_id = "2147607468"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Muldrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_10_2 = "*\\AC:\\Documents and Settings\\Andres\\Escritorio\\Cactus.exe\\Cactus.dll\\X.vbp" wide //weight: 10
        $x_10_3 = "FirewallEnabled" wide //weight: 10
        $x_10_4 = "USERPROFILE" wide //weight: 10
        $x_10_5 = "llehS.tpircSW" wide //weight: 10
        $x_10_6 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS\\UCKH" wide //weight: 10
        $x_10_7 = "RegWrite" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Muldrop_V_2147741519_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Muldrop.V!MTB"
        threat_id = "2147741519"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Muldrop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 00 55 00 c5 00 69 00 c9 00 6f 00 72 00 cf 00 d1 00}  //weight: 2, accuracy: High
        $x_2_2 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 72 00 f9 00 6e 00 61 00 6d 00 65 00 20 00 22 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

