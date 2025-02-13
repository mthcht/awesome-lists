rule Trojan_MSIL_DllInjector_ZC_2147759068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInjector.ZC!MTB"
        threat_id = "2147759068"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LoadImageToMemory" ascii //weight: 1
        $x_1_2 = "ReadProcessMemory" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "Injected!" wide //weight: 1
        $x_1_5 = {67 69 67 63 61 70 61 73 74 65 5c 6c 6f 61 64 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c [0-32] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_6 = "set_AsyncInjection" ascii //weight: 1
        $x_1_7 = "ManualMapInjector" ascii //weight: 1
        $x_1_8 = "get_AsyncInjection" ascii //weight: 1
        $x_1_9 = "ManualMapInjection.Injection.Types" ascii //weight: 1
        $x_1_10 = "AntiFiddler" ascii //weight: 1
        $x_1_11 = "Copy HWID" wide //weight: 1
        $x_1_12 = "csgo" wide //weight: 1
        $x_1_13 = "Stable" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_MSIL_DllInjector_ZD_2147759069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInjector.ZD!MTB"
        threat_id = "2147759069"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "000webhostapp.com" wide //weight: 1
        $x_1_2 = "Enter your Password." wide //weight: 1
        $x_1_3 = "Cheat Coder" wide //weight: 1
        $x_1_4 = "injected successfully" wide //weight: 1
        $x_1_5 = "doritos.club" wide //weight: 1
        $x_1_6 = {4d 00 65 00 67 00 61 00 44 00 75 00 6d 00 70 00 65 00 72 00 20 00 [0-10] 20 00 62 00 79 00 20 00 43 00 6f 00 64 00 65 00 43 00 72 00 61 00 63 00 6b 00 65 00 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

