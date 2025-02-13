rule Ransom_Win32_Haknata_A_2147719870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Haknata.A!rsm"
        threat_id = "2147719870"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Haknata"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NMoreira" ascii //weight: 1
        $x_1_2 = ".HakunaMatata" ascii //weight: 1
        $x_2_3 = "*bootmgr* *boot* *boot* *CONFIG.SYS*" ascii //weight: 2
        $x_2_4 = "*\\java\\* *\\TeamViewer\\* *\\windows\\*" ascii //weight: 2
        $x_1_5 = "<img src='data:image/gif;base64,R0lGOD" ascii //weight: 1
        $x_1_6 = "All your files are encrypted.Using AES256-bit encryption" ascii //weight: 1
        $x_1_7 = "Crypter with problems. Screwed up configuration." ascii //weight: 1
        $x_1_8 = "Hugs, NMoreira Core Dev." ascii //weight: 1
        $x_1_9 = "Recovers files yako.html" ascii //weight: 1
        $x_1_10 = "start= disabled" ascii //weight: 1
        $x_1_11 = "CALL  ChangeStartMode 'Disabled'" ascii //weight: 1
        $x_1_12 = "Bitmenssages" ascii //weight: 1
        $x_1_13 = "getting is the key" ascii //weight: 1
        $x_1_14 = "notbadbat,.bat" ascii //weight: 1
        $x_1_15 = "supermetroidrules" ascii //weight: 1
        $x_1_16 = "%SystemRoot%\\System32\\shell32.dll,47" ascii //weight: 1
        $x_1_17 = "CrypterApp::s_crypterApp" ascii //weight: 1
        $x_1_18 = "if exist \"%S\" goto WaitAndDelete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

