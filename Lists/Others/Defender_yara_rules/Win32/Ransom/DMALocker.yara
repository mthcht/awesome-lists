rule Ransom_Win32_DMALocker_A_2147709052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DMALocker.A"
        threat_id = "2147709052"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DMALocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DMA Locker" ascii //weight: 1
        $x_1_2 = "Otwieranie pliku:" ascii //weight: 1
        $x_1_3 = "cryptedinfo" ascii //weight: 1
        $x_1_4 = "s-advice-on-cryptolocker-just-pa" ascii //weight: 1
        $x_1_5 = "DMALOCK" ascii //weight: 1
        $x_1_6 = "IF FILES UNLOCKING PROCEDURE IS ALREADY WORKING," ascii //weight: 1
        $x_1_7 = "HOW TO PAY US AND UNLOCK YOUR FILES?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_DMALocker_B_2147712019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DMALocker.B"
        threat_id = "2147712019"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DMALocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[+] Decrypting succeeded, saving: %s" wide //weight: 2
        $x_2_2 = "3. If you already have Bitcoins, pay us" wide //weight: 2
        $x_2_3 = "\\decrypting.txt" wide //weight: 2
        $x_2_4 = "\\cryptinfo.txt" wide //weight: 2
        $x_1_5 = {42 00 41 00 43 00 4b 00 47 00 52 00 4f 00 55 00 4e 00 44 00 00 00}  //weight: 1, accuracy: High
        $x_2_6 = "DMA Locker" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_DMALocker_B_2147712019_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DMALocker.B"
        threat_id = "2147712019"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DMALocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DMA Locker 4.0" ascii //weight: 1
        $x_1_2 = "DMALOCK.ENCDECDD" ascii //weight: 1
        $x_1_3 = "!DMALOCK4.0" ascii //weight: 1
        $x_1_4 = {00 64 6d 61 5f 69 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 64 6d 61 5f 70 75 62 6c 69 63 5f 6b 65 79 00}  //weight: 1, accuracy: High
        $x_1_6 = "Executing fist knock" ascii //weight: 1
        $x_1_7 = "/crypto/gate?action=" ascii //weight: 1
        $x_1_8 = "&botId=%s" ascii //weight: 1
        $x_1_9 = "&transactionId=%s" ascii //weight: 1
        $x_2_10 = "//%s/crypto/client_payment_instructions?botId=%s" ascii //weight: 2
        $x_2_11 = "//%s/crypto/client_free_decrypt?botId=%s" ascii //weight: 2
        $x_1_12 = "ransom_amount_increase_amount" ascii //weight: 1
        $x_1_13 = "ransom_amount_increase_timestamp" ascii //weight: 1
        $x_1_14 = "\\vssadmin.exe delete shadows" ascii //weight: 1
        $x_1_15 = "@zerobit.email" ascii //weight: 1
        $x_2_16 = "DMALOCK 36:54:11:05:09:14:76:22" ascii //weight: 2
        $x_1_17 = "\\cryptinfo.txt" ascii //weight: 1
        $x_1_18 = "\\svchosd.exe" ascii //weight: 1
        $x_1_19 = "\\decrypting.txt" ascii //weight: 1
        $x_1_20 = "\\select.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_DMALocker_A_2147712022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DMALocker.A!!DMALocker.gen!A"
        threat_id = "2147712022"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DMALocker"
        severity = "Critical"
        info = "DMALocker: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DMA Locker" ascii //weight: 1
        $x_1_2 = "Otwieranie pliku:" ascii //weight: 1
        $x_1_3 = "cryptedinfo" ascii //weight: 1
        $x_1_4 = "s-advice-on-cryptolocker-just-pa" ascii //weight: 1
        $x_1_5 = "DMALOCK" ascii //weight: 1
        $x_1_6 = "IF FILES UNLOCKING PROCEDURE IS ALREADY WORKING," ascii //weight: 1
        $x_1_7 = "HOW TO PAY US AND UNLOCK YOUR FILES?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_DMALocker_B_2147712023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DMALocker.B!!DMALocker.gen!A"
        threat_id = "2147712023"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DMALocker"
        severity = "Critical"
        info = "DMALocker: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DMA Locker 4.0" ascii //weight: 1
        $x_1_2 = "DMALOCK.ENCDECDD" ascii //weight: 1
        $x_1_3 = "!DMALOCK4.0" ascii //weight: 1
        $x_1_4 = {00 64 6d 61 5f 69 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 64 6d 61 5f 70 75 62 6c 69 63 5f 6b 65 79 00}  //weight: 1, accuracy: High
        $x_1_6 = "Executing fist knock" ascii //weight: 1
        $x_1_7 = "/crypto/gate?action=" ascii //weight: 1
        $x_1_8 = "&botId=%s" ascii //weight: 1
        $x_1_9 = "&transactionId=%s" ascii //weight: 1
        $x_2_10 = "//%s/crypto/client_payment_instructions?botId=%s" ascii //weight: 2
        $x_2_11 = "//%s/crypto/client_free_decrypt?botId=%s" ascii //weight: 2
        $x_1_12 = "ransom_amount_increase_amount" ascii //weight: 1
        $x_1_13 = "ransom_amount_increase_timestamp" ascii //weight: 1
        $x_1_14 = "\\vssadmin.exe delete shadows" ascii //weight: 1
        $x_1_15 = "@zerobit.email" ascii //weight: 1
        $x_2_16 = "DMALOCK 36:54:11:05:09:14:76:22" ascii //weight: 2
        $x_1_17 = "\\cryptinfo.txt" ascii //weight: 1
        $x_1_18 = "\\svchosd.exe" ascii //weight: 1
        $x_1_19 = "\\decrypting.txt" ascii //weight: 1
        $x_1_20 = "\\select.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

