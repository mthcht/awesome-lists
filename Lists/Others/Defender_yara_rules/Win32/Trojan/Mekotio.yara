rule Trojan_Win32_Mekotio_RS_2147837260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mekotio.RS!MTB"
        threat_id = "2147837260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mekotio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uabk609421n0psze4831" ascii //weight: 1
        $x_1_2 = "gtj24r7ktl470" ascii //weight: 1
        $x_1_3 = "WinHttpGetIEProxyConfigForCurrentUser" ascii //weight: 1
        $x_1_4 = "themida" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mekotio_YAA_2147902522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mekotio.YAA!MTB"
        threat_id = "2147902522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mekotio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dbkFCallWrapperAddr" ascii //weight: 1
        $x_1_2 = "__dbk_fcall_wrapper" ascii //weight: 1
        $x_1_3 = "TMethodImplementationIntercept" ascii //weight: 1
        $x_1_4 = {48 40 33 da 03 c9 66 0f a3 c1 13 f2 0f c8 ff e6}  //weight: 1, accuracy: High
        $x_1_5 = {32 c3 c1 c1 ba 66 0b c9 66 0f a3 c9 d0 c8 66 0f ab c9 fe c1 66 ff c9 32 c1 66 81 e9 92 b2 66 d3 c9 fe c8 2b c9 34 1d c1 e1 92 c0 e1 63 d0 c8 32 d8 66 23 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

