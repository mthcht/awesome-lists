rule Ransom_Win32_LockerGoga_2147734273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockerGoga"
        threat_id = "2147734273"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockerGoga"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 3d 00 2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 00 00 5c 00 3f 00 3f 00 5c 00 5c 00 00 00 20 46 41 49 4c 45 44}  //weight: 1, accuracy: High
        $x_1_2 = {52 45 41 44 4d 45 5f 4c 4f 43 4b 45 44 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockerGoga_B_2147734298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockerGoga.B"
        threat_id = "2147734298"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockerGoga"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 72 79 70 74 6f 2d 6c 6f 63 6b 65 72 5c 74 70 6c 73 5f 4d 53 56 43 5c [0-32] 2f 65 78 63 65 70 74 69 6f 6e 2f 64 65 74 61 69 6c 2f 65 78 63 65 70 74 69 6f 6e 5f 70 74 72 2e 68 70 70}  //weight: 1, accuracy: Low
        $x_1_2 = "(doc|dot|wbk|docx|dotx|docb|xlm|xlsx|xltx|xlsb|xlw|ppt|pot|pps|pptx|potx|ppsx|sldx|pdf)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockerGoga_D_2147734301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockerGoga.D"
        threat_id = "2147734301"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockerGoga"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 6c 6e 6b 00 00 00 00 2e 64 6f 63 00 00 00 00 2e 64 6f 74 00 00 00 00 2e 64 6f 63 78 00 00 00 2e 64 6f 63 62 00 00 00 2e 64 6f 74 78 00 00 00 64 6f 74 62 00 00 00 00 2e 77 6b 62 00 00 00 00 2e 78 6d 6c 00}  //weight: 10, accuracy: High
        $x_10_2 = "doc|dot|wbk|docx|dotx|docb|xlm|xlsx|xltx|xlsb|xlw|ppt|pot|pps|pptx|potx|ppsx|sldx|pdf" wide //weight: 10
        $x_10_3 = "(do[ct][xb]?|wbk|xlm|xlsx|xltx|xlsb|xlw|pp[ts]|pot|p[op][st]x|sldx|pdf|db|sql)" wide //weight: 10
        $x_10_4 = "(\\(x86\\))?|[A-Za-z]:\\\\(pagefile\\.sys|hiberfil\\.sys|perflogs|boot.*|programdata|system volume information" wide //weight: 10
        $x_10_5 = "jmCFIbUSLG+XNcT1V3riHlpNAehoj1s7Y50fIFfRZG/5MwAyhwnISxXkjUWhUGbE" ascii //weight: 10
        $x_10_6 = "\\crypto-locker\\tpls_MSVC" ascii //weight: 10
        $x_10_7 = "\\crypto-locker\\cryptopp\\src" ascii //weight: 10
        $x_10_8 = {69 6e 74 65 72 66 61 63 65 00 00 00 73 65 74 00 6e 65 74 73 68 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_5_9 = "txt|(ntuser|usrclass)\\" wide //weight: 5
        $x_5_10 = "(dat|ini)|desktop\\.ini|.+\\.(lnk|sys|dll|locked)" wide //weight: 5
        $x_5_11 = "(dat|ini)|desktop\\ini|+\\(lnk|sys|dll|locked)" wide //weight: 5
        $x_5_12 = "microsoft\\\\windows\\\\burn|gdipfontcachev1\\.dat" wide //weight: 5
        $x_5_13 = {73 76 63 68 30 73 74 2e [0-5] 2e 65 78 65}  //weight: 5, accuracy: Low
        $x_5_14 = {c7 85 5c fe ff ff 47 4f 47 41 6a 00 50}  //weight: 5, accuracy: High
        $x_5_15 = {c7 85 90 fe ff ff 67 6f 67 61 6a 00 50}  //weight: 5, accuracy: High
        $x_5_16 = "DharmaParrack@protonmail.com" ascii //weight: 5
        $x_5_17 = "wyattpettigrew8922555@mail.com" ascii //weight: 5
        $x_2_18 = "MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB" ascii //weight: 2
        $x_2_19 = {63 3a 2f 63 6c 2e 6c 6f 67 00}  //weight: 2, accuracy: High
        $x_2_20 = {6c 00 6f 00 63 00 6b 00 65 00 64 00 00 00}  //weight: 2, accuracy: High
        $x_2_21 = {52 45 41 44 4d 45 5f 4c 4f 43 4b 45 44 2e 74 78 74 00}  //weight: 2, accuracy: High
        $x_2_22 = {52 45 41 44 4d 45 2d 4e 4f 57 2e 74 78 74 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_LockerGoga_C_2147734302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockerGoga.C"
        threat_id = "2147734302"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockerGoga"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "work\\Projects\\LockerGoga" ascii //weight: 1
        $x_1_2 = "CryptoLocker" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockerGoga_STR_2147809871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockerGoga.STR!MTB"
        threat_id = "2147809871"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockerGoga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mirc\\script.ini.locked" ascii //weight: 1
        $x_1_2 = "joanna.smith@domain.com" ascii //weight: 1
        $x_1_3 = "choice /t 1 /d y /n >nul" ascii //weight: 1
        $x_1_4 = "del %0" ascii //weight: 1
        $x_1_5 = ".locked" ascii //weight: 1
        $x_1_6 = "xxxx.onion/" ascii //weight: 1
        $x_1_7 = "RECOVERY_README" ascii //weight: 1
        $x_1_8 = "ShellExecuteA" ascii //weight: 1
        $x_1_9 = "DecodingLookupArray" ascii //weight: 1
        $x_1_10 = "Crypto++ RNG" ascii //weight: 1
        $x_1_11 = ".torrent" ascii //weight: 1
        $x_1_12 = ".locky" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockerGoga_E_2147913047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockerGoga.E"
        threat_id = "2147913047"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockerGoga"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\.(doc|dot|wbk|docx|dotx|docb|xlm|xlsx|xltx|xlsb|xlw|ppt|pot|pps|pptx|potx|ppsx|sldx|pdf)" wide //weight: 1
        $x_1_2 = "|[A-Za-z]:\\cl.log" wide //weight: 1
        $x_1_3 = "\\crypto-locker\\" ascii //weight: 1
        $x_1_4 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 ?? ?? ?? (00) (00) 4d 00 6c 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 2c 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 00 00 20 46 41 49 4c 45 44 20 00 00 00 00 20 00 00 00 20 75 6e 6b 6e 6f 77 6e 20 65 78 63 65 70 74 69 6f 6e 33 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = "This may lead to the impossibility of recovery of the certain files." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

