rule Trojan_Win32_ShadeCrypt_SR_2147745219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShadeCrypt.SR!!Shade.gen!SD"
        threat_id = "2147745219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadeCrypt"
        severity = "Critical"
        info = "Shade: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "SD: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pwdcheck.vbs" ascii //weight: 1
        $x_1_2 = "postsetup.cmd" ascii //weight: 1
        $x_1_3 = "Postconnect.xml" ascii //weight: 1
        $x_1_4 = "regini.txt" ascii //weight: 1
        $x_1_5 = "regset.vbsc" ascii //weight: 1
        $x_1_6 = "release notes.docx" ascii //weight: 1
        $x_1_7 = "--ignore-missing-torrc" ascii //weight: 1
        $x_1_8 = "groove.net\\grooveforms3\\formsstyles\\brightorange\\background.gif" ascii //weight: 1
        $x_1_9 = "\\DataArchive\\microsoft\\crypto\\rsa\\machinekeys\\" ascii //weight: 1
        $x_1_10 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 1
        $x_1_11 = "\\Samples\\Dumpa222.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

