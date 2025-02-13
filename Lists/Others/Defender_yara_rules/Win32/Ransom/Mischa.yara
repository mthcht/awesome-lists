rule Ransom_Win32_Mischa_A_2147711821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mischa.A"
        threat_id = "2147711821"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mischa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "<h1>You became victim of the MISCHA RANSOMWARE!</h1>" ascii //weight: 2
        $x_1_2 = "://mischa" ascii //weight: 1
        $x_1_3 = "<title>MISCHA Ransomware</title>" ascii //weight: 1
        $x_1_4 = "Mischa.dll" ascii //weight: 1
        $x_1_5 = "YOUR_FILES_ARE_ENCRYPTED" ascii //weight: 1
        $x_1_6 = "##URL1##<br/> ##URL2##" ascii //weight: 1
        $x_1_7 = "##CODE## </body></html>" ascii //weight: 1
        $x_1_8 = {00 2e 70 73 70 69 6d 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 5c 24 52 65 63 79 63 6c 65 2e 42 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Mischa_A_2147711822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mischa.A!!Mischa.gen!A"
        threat_id = "2147711822"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mischa"
        severity = "Critical"
        info = "Mischa: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "<h1>You became victim of the MISCHA RANSOMWARE!</h1>" ascii //weight: 2
        $x_1_2 = "://mischa" ascii //weight: 1
        $x_1_3 = "<title>MISCHA Ransomware</title>" ascii //weight: 1
        $x_1_4 = "Mischa.dll" ascii //weight: 1
        $x_1_5 = "YOUR_FILES_ARE_ENCRYPTED" ascii //weight: 1
        $x_1_6 = "##URL1##<br/> ##URL2##" ascii //weight: 1
        $x_1_7 = "##CODE## </body></html>" ascii //weight: 1
        $x_1_8 = {00 2e 70 73 70 69 6d 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 5c 24 52 65 63 79 63 6c 65 2e 42 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

