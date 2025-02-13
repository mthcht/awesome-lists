rule Worm_Win32_Bankim_A_2147582744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bankim.A"
        threat_id = "2147582744"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bankim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Msnj\\Project" wide //weight: 2
        $x_2_2 = "WINDOWS\\CURRENTVERSION\\RUN" wide //weight: 2
        $x_1_3 = "Messenger" wide //weight: 1
        $x_1_4 = "system\\msmnsgr.exe" wide //weight: 1
        $x_2_5 = "{ENTER}" wide //weight: 2
        $x_2_6 = "WINDIR" wide //weight: 2
        $x_1_7 = "system32\\sv" wide //weight: 1
        $x_1_8 = "http://" wide //weight: 1
        $x_2_9 = "yahoo.com.br" wide //weight: 2
        $x_2_10 = "svhootss.exe" wide //weight: 2
        $x_2_11 = "svhotss.exe" wide //weight: 2
        $x_1_12 = "Falha Na Mem" wide //weight: 1
        $x_1_13 = "SYSTEM ERROR" wide //weight: 1
        $x_1_14 = "Requerido Windows NT Server" wide //weight: 1
        $x_1_15 = "O aplicativo" wide //weight: 1
        $x_1_16 = "o foi localizado" wide //weight: 1
        $x_1_17 = "sua localiza" wide //weight: 1
        $x_2_18 = "FOTOS_" ascii //weight: 2
        $x_2_19 = "MessengerAPI" ascii //weight: 2
        $x_2_20 = "Messenger\\msmsgs" ascii //weight: 2
        $x_3_21 = "MSN_OnIMWindowCreated" ascii //weight: 3
        $x_1_22 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_23 = "GetWindowTextA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_2_*) and 11 of ($x_1_*))) or
            ((8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((9 of ($x_2_*) and 7 of ($x_1_*))) or
            ((10 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 9 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 10 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

