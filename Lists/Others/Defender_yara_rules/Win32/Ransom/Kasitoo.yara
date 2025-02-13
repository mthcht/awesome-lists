rule Ransom_Win32_Kasitoo_A_2147726238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Kasitoo.A!rsm"
        threat_id = "2147726238"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Kasitoo"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "gpg.exe --recipient qwerty  -o \"%s%s.%d.qwerty\" --encrypt \"%s%s" ascii //weight: 3
        $x_3_2 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 65 6e 63 72 79 70 74 65 64 20 2e 20 4d 61 69 6c 20 [0-64] 2e 20 53 65 6e 64 20 79 6f 75 72 20 49 44}  //weight: 3, accuracy: Low
        $x_3_3 = "Note! You have only 72 hours for write on e-mail (see below) or all your files will be lost" ascii //weight: 3
        $x_1_4 = {65 63 68 6f 20 25 73 20 [0-4] 20 22 25 73 2f 52 45 41 44 4d 45 5f 44 45 43 52 59 50 54 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = "shred -f -u -n 1 \"%s%s" ascii //weight: 1
        $x_1_6 = "taskkill /F /IM sql" ascii //weight: 1
        $x_1_7 = "taskkill /F /IM chrome.exe" ascii //weight: 1
        $x_1_8 = "taskkill /F /IM ie.exe" ascii //weight: 1
        $x_1_9 = "taskkill /F /IM firefox.exe" ascii //weight: 1
        $x_1_10 = "taskkill /F /IM opera.exe" ascii //weight: 1
        $x_1_11 = "taskkill /F /IM safari.exe" ascii //weight: 1
        $x_1_12 = "taskkill /F /IM taskmgr.exe" ascii //weight: 1
        $x_1_13 = "taskkill /F /IM 1c" ascii //weight: 1
        $x_1_14 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
        $x_1_15 = "wmic shadowcopy delete" ascii //weight: 1
        $x_1_16 = "bcdedit.exe bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_17 = "bcdedit.exe bcdedit /set {default} recoveryenabled no" ascii //weight: 1
        $x_1_18 = "wbadmin.exe wbadmin delete catalog -quiet" ascii //weight: 1
        $x_1_19 = "del /Q /F /S %s$recycle.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

