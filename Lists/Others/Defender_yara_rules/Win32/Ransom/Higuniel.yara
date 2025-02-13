rule Ransom_Win32_Higuniel_A_2147725777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Higuniel.A"
        threat_id = "2147725777"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Higuniel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#PreRun" ascii //weight: 1
        $x_1_2 = "#PostRun" ascii //weight: 1
        $x_1_3 = "#ExtensionIgnore" ascii //weight: 1
        $x_1_4 = "#TXT" ascii //weight: 1
        $x_2_5 = "ReadMe_Decryptor.txt" ascii //weight: 2
        $x_4_6 = "sc stop wscsvc" ascii //weight: 4
        $x_4_7 = "sc stop WinDefend" ascii //weight: 4
        $x_4_8 = "sc stop wuauserv" ascii //weight: 4
        $x_4_9 = "sc stop BITS" ascii //weight: 4
        $x_4_10 = "sc stop ERSvc" ascii //weight: 4
        $x_4_11 = "sc stop WerSvc" ascii //weight: 4
        $x_8_12 = "cmd.exe /c bcdedit /set {default} recoveryenabled No" ascii //weight: 8
        $x_8_13 = "cmd.exe /c bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 8
        $x_8_14 = "cmd.exe /c vssadmin delete shadows /all /quiet" ascii //weight: 8
        $x_8_15 = "cmd.exe /c wmic shadowcopy delete" ascii //weight: 8
        $x_8_16 = "cmd.exe /c wbadmin delete catalog -quiet" ascii //weight: 8
        $x_16_17 = "taskkill /f /im MSExchange*" ascii //weight: 16
        $x_16_18 = "taskkill /f /im Microsoft.Exchange.*" ascii //weight: 16
        $x_16_19 = "taskkill /f /im sqlserver.exe" ascii //weight: 16
        $x_16_20 = "taskkill /f /im sqlwriter.exe" ascii //weight: 16
        $x_32_21 = "All your files have been encrypted due to a security problem with your PC. If you want to restore them, write us to the e-mail decryptor@cock.li" ascii //weight: 32
        $x_32_22 = "All your files have been encrypted due to a security problem with your PC. If you want to restore them, write us to the e-mail: aidcompany@tutanota.com" ascii //weight: 32
        $x_32_23 = "In case of no answer in 24 hours write us to theese e-mails: masterdecrypt@openmailbox.org" ascii //weight: 32
        $x_32_24 = "In case of no answer in 48 hours write us to theese e-mails: aidcompanu@cock.li" ascii //weight: 32
        $x_32_25 = "You have to pay for decryption in Bitcoins. The price depends on how fast you write to us." ascii //weight: 32
        $x_32_26 = "Before paying you can send us up to 5 files for free decryption." ascii //weight: 32
        $x_32_27 = "After payment we will send you the decryption tool that will decrypt all your files." ascii //weight: 32
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_8_*) and 5 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_8_*) and 6 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_8_*) and 6 of ($x_4_*) and 1 of ($x_2_*))) or
            ((3 of ($x_8_*) and 3 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_8_*) and 4 of ($x_4_*) and 2 of ($x_1_*))) or
            ((3 of ($x_8_*) and 4 of ($x_4_*) and 1 of ($x_2_*))) or
            ((3 of ($x_8_*) and 5 of ($x_4_*))) or
            ((4 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_8_*) and 2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((4 of ($x_8_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((4 of ($x_8_*) and 3 of ($x_4_*))) or
            ((5 of ($x_8_*) and 2 of ($x_1_*))) or
            ((5 of ($x_8_*) and 1 of ($x_2_*))) or
            ((5 of ($x_8_*) and 1 of ($x_4_*))) or
            ((1 of ($x_16_*) and 5 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_16_*) and 6 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_16_*) and 6 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_8_*) and 3 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_16_*) and 1 of ($x_8_*) and 4 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_16_*) and 1 of ($x_8_*) and 4 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_8_*) and 5 of ($x_4_*))) or
            ((1 of ($x_16_*) and 2 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_16_*) and 2 of ($x_8_*) and 2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_16_*) and 2 of ($x_8_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 2 of ($x_8_*) and 3 of ($x_4_*))) or
            ((1 of ($x_16_*) and 3 of ($x_8_*) and 2 of ($x_1_*))) or
            ((1 of ($x_16_*) and 3 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 3 of ($x_8_*) and 1 of ($x_4_*))) or
            ((1 of ($x_16_*) and 4 of ($x_8_*))) or
            ((2 of ($x_16_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_16_*) and 2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_16_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_16_*) and 3 of ($x_4_*))) or
            ((2 of ($x_16_*) and 1 of ($x_8_*) and 2 of ($x_1_*))) or
            ((2 of ($x_16_*) and 1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((2 of ($x_16_*) and 1 of ($x_8_*) and 1 of ($x_4_*))) or
            ((2 of ($x_16_*) and 2 of ($x_8_*))) or
            ((3 of ($x_16_*))) or
            ((1 of ($x_32_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_32_*) and 2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_32_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_32_*) and 3 of ($x_4_*))) or
            ((1 of ($x_32_*) and 1 of ($x_8_*) and 2 of ($x_1_*))) or
            ((1 of ($x_32_*) and 1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_32_*) and 1 of ($x_8_*) and 1 of ($x_4_*))) or
            ((1 of ($x_32_*) and 2 of ($x_8_*))) or
            ((1 of ($x_32_*) and 1 of ($x_16_*))) or
            ((2 of ($x_32_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Higuniel_B_2147725778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Higuniel.B"
        threat_id = "2147725778"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Higuniel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "All your files have been encrypted !" ascii //weight: 2
        $x_2_2 = "If you want restore your files write on email - twist@airmail.cc" ascii //weight: 2
        $x_2_3 = "If you want restore your files write on email - blind@airmail.cc" ascii //weight: 2
        $x_2_4 = "How_Decrypt_Files.txt" ascii //weight: 2
        $x_2_5 = ".[twist@airmail.cc].twist" wide //weight: 2
        $x_2_6 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

