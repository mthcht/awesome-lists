rule Trojan_Win64_Growtopia_NG_2147895390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Growtopia.NG!MTB"
        threat_id = "2147895390"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FEAR Proxy.pdb" ascii //weight: 1
        $x_1_2 = "4Unable To serialize this world" ascii //weight: 1
        $x_1_3 = "beta_server" ascii //weight: 1
        $x_1_4 = "Kingdom Premium Source" ascii //weight: 1
        $x_1_5 = "CryptEncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Growtopia_NGA_2147901532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Growtopia.NGA!MTB"
        threat_id = "2147901532"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Baglanti hatasi!" ascii //weight: 1
        $x_1_2 = "Kulo Proxy.pdb" ascii //weight: 1
        $x_1_3 = "3bapoy8RH1" ascii //weight: 1
        $x_1_4 = "Connecting to Proxy Server..." ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Growtopia_NA_2147901569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Growtopia.NA!MTB"
        threat_id = "2147901569"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ascent Premium Proxy.pdb" ascii //weight: 1
        $x_1_2 = "Decoded Items" ascii //weight: 1
        $x_1_3 = "Unable To serialize this world" ascii //weight: 1
        $x_1_4 = "Something gone wrong while decoding .dat file!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

