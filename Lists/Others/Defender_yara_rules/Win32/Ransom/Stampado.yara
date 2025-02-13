rule Ransom_Win32_Stampado_A_2147717855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stampado.A"
        threat_id = "2147717855"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stampado"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CurrentVersion\\Run\" , \"Windows Update\"" wide //weight: 1
        $x_1_2 = "& \".locked\"" wide //weight: 1
        $x_1_3 = "All your files have been encrypted" wide //weight: 1
        $x_1_4 = "\"shellexecute=myDisk\\drivers.exe\"" wide //weight: 1
        $x_1_5 = "@APPDATADIR & \"\\scvhost.exe\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Stampado_A_2147721386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stampado.A!!Stampado.gen!A"
        threat_id = "2147721386"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stampado"
        severity = "Critical"
        info = "Stampado: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 [0-4] 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-4] 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65}  //weight: 1, accuracy: Low
        $x_1_3 = ".locked" ascii //weight: 1
        $x_1_4 = "philadelphia_debug.txt" ascii //weight: 1
        $x_1_5 = "Done infecting network" ascii //weight: 1
        $x_1_6 = "Encrypted filename" ascii //weight: 1
        $x_2_7 = "shellexecute=myDisk\\drivers.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Stampado_RA_2147837666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stampado.RA!MTB"
        threat_id = "2147837666"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stampado"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_CRYPT_ENCRYPTDATA ( $BTEMPDATA , $VCRYPTKEY , $CALG_USERKEY , TRUE )" ascii //weight: 1
        $x_1_2 = "RUN ( \"diskpart /s C:\\ProgramData\\m.txt\" , \"\" , @SW_HIDE )" ascii //weight: 1
        $x_1_3 = "RUN ( \"takeown /f V:\\Boot /r\" , \"\" , @SW_HIDE )" ascii //weight: 1
        $x_1_4 = "RUN ( \"takeown /f V:\\Recovery /r\" , \"\" , @SW_HIDE )" ascii //weight: 1
        $x_1_5 = "DIRREMOVE ( \"V:\\Recovery\" , 1 )" ascii //weight: 1
        $x_1_6 = "DIRREMOVE ( \"V:\\Boot\" , 1 )" ascii //weight: 1
        $x_1_7 = "FILEDELETE ( \"Uninstall.exe\" )" ascii //weight: 1
        $x_1_8 = "WIPEFILES ( \"C:\\\" , $EXTENSIONS_FOR_DRIVES )" ascii //weight: 1
        $x_1_9 = " _RUNCMD ( RANDOM ( 1000000 , 9999999 , 1 ) , \"vssadmin.exe Delete Shadows /All /Quiet\" )" ascii //weight: 1
        $x_1_10 = " _RUNCMD ( RANDOM ( 1000000 , 9999999 , 1 ) , \"bcdedit /set {default} recoveryenabled No\" )" ascii //weight: 1
        $x_1_11 = " _RUNCMD ( RANDOM ( 1000000 , 9999999 , 1 ) , \"bcdedit /set {default} bootstatuspolicy ignoreallfailures\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

