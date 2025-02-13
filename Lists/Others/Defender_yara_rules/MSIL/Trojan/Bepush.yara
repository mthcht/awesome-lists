rule Trojan_MSIL_Bepush_B_2147681662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bepush.B"
        threat_id = "2147681662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bepush"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "yok.txt" wide //weight: 1
        $x_1_2 = "var.txt" wide //weight: 1
        $x_10_3 = "\\FPlay.pdb" ascii //weight: 10
        $x_10_4 = "/index_start.html" wide //weight: 10
        $x_10_5 = {08 09 8e 69 fe 04 13 09 11 09 3a a1 fe ff ff 7e 11 00 00 04 16 fe 01 13 09 11 09 2d 12 00 7e 08 00 00 04 72 ?? ?? 00 70 28 ?? 00 00 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Bepush_B_2147681662_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bepush.B"
        threat_id = "2147681662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bepush"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 68 72 6f 6d 65 56 61 72 4d 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {4b 69 6c 6c 43 68 72 6f 6d 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "Reg deneme..." wide //weight: 1
        $x_1_4 = "Create log123..." wide //weight: 1
        $x_1_5 = "/index_start.html" wide //weight: 1
        $x_1_6 = "/yok.txt" wide //weight: 1
        $x_1_7 = "Chrome extension {0} installed..." wide //weight: 1
        $x_1_8 = "Extension: {0} download..." wide //weight: 1
        $x_1_9 = "FyPlayer01.Properties" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_MSIL_Bepush_C_2147685203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bepush.C"
        threat_id = "2147685203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bepush"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KillChrome" ascii //weight: 1
        $x_1_2 = "KillFirefox" ascii //weight: 1
        $x_1_3 = "/extFiles" ascii //weight: 1
        $x_1_4 = "user_pref(\"browser.startup.homepage\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bepush_A_2147687564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bepush.gen!A"
        threat_id = "2147687564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bepush"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/extFiles/control" ascii //weight: 1
        $x_1_2 = "\\SExtension" ascii //weight: 1
        $x_1_3 = "WebClient For Extensions" ascii //weight: 1
        $x_1_4 = "FLVPlay.exe" ascii //weight: 1
        $x_1_5 = "FLVUpdate" ascii //weight: 1
        $x_1_6 = "agentofex.com" ascii //weight: 1
        $x_1_7 = "eklentidunyasi.com" ascii //weight: 1
        $x_1_8 = "enoticer.com" ascii //weight: 1
        $x_1_9 = "showmaskonnn.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_MSIL_Bepush_A_2147687564_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bepush.gen!A"
        threat_id = "2147687564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bepush"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "version\".*?:.*?\"(.*?)" ascii //weight: 1
        $x_1_2 = "<em:id>(.*?)</em:id>" ascii //weight: 1
        $x_1_3 = "restore_on_startup" ascii //weight: 1
        $x_1_4 = "ack_prompt_count" ascii //weight: 1
        $x_1_5 = "Chrome extension {0}" ascii //weight: 1
        $x_1_6 = "Firefox extension {0}" ascii //weight: 1
        $x_1_7 = "\\Chrome\\Extensions" ascii //weight: 1
        $x_1_8 = "\\Firefox\\Extensions" ascii //weight: 1
        $x_1_9 = "\\SExtension" ascii //weight: 1
        $x_1_10 = "Reg deneme..." ascii //weight: 1
        $x_1_11 = "Create log123..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_MSIL_Bepush_F_2147690866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bepush.F"
        threat_id = "2147690866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bepush"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Extension: {0} download..." wide //weight: 1
        $x_1_2 = "/yok.txt" wide //weight: 1
        $x_1_3 = "Chrome extension {0} installed..." wide //weight: 1
        $x_1_4 = "Chrome eklenti dosya yolu yanl" wide //weight: 1
        $x_1_5 = "Dosya silmede veya ta" wide //weight: 1
        $x_1_6 = "FHdPlayer3.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bepush_H_2147696491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bepush.H"
        threat_id = "2147696491"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bepush"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vaydile" wide //weight: 1
        $x_1_2 = {76 00 6d 00 77 00 61 00 72 00 65 00 [0-5] 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 42 00 6f 00 78 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Mozila\\sabit.au3" wide //weight: 1
        $x_1_4 = "\\Mozila\\force.au3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bepush_I_2147697089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bepush.I"
        threat_id = "2147697089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bepush"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 61 00 62 00 69 00 74 00 60 00 65 00 6b 00 [0-6] 61 00 75 00 [0-6] 75 00 70 00 [0-6] 66 00 6f 00 72 00 63 00 65 00 [0-6] 72 00 65 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

