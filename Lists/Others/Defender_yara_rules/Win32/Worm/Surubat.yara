rule Worm_Win32_Surubat_A_2147575114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Surubat.A"
        threat_id = "2147575114"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Surubat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "please read attachment bellow, and please reply to me..!!!" ascii //weight: 2
        $x_2_2 = "hope we don't have miss understanding" ascii //weight: 2
        $x_2_3 = "thank's...!!!" ascii //weight: 2
        $x_2_4 = "This is our report of naked isue" ascii //weight: 2
        $x_2_5 = "You Have Done Something Which Can Harm Your System" ascii //weight: 2
        $x_2_6 = "To Prevent From Damage, System Has Been Restart" ascii //weight: 2
        $x_2_7 = "Tamara_Blezynsky" ascii //weight: 2
        $x_2_8 = "_Peta_Instalasi_Nuklir_Israel.zip" ascii //weight: 2
        $x_2_9 = "_Peta_Instalasi_Nuklir_Israel.exe" ascii //weight: 2
        $x_1_10 = "Warn on Mapi Send" ascii //weight: 1
        $x_1_11 = "MAPISendMail" ascii //weight: 1
        $x_1_12 = "MAPIFreeBuffer" ascii //weight: 1
        $x_1_13 = "MAPIReadMail" ascii //weight: 1
        $x_1_14 = "MAPIFindNext" ascii //weight: 1
        $x_1_15 = "MAPILogon" ascii //weight: 1
        $x_1_16 = "POP3 User Name" ascii //weight: 1
        $x_1_17 = "Default User ID" ascii //weight: 1
        $x_1_18 = "Identities" ascii //weight: 1
        $x_1_19 = "systems.exe" ascii //weight: 1
        $x_1_20 = "mailing.dll" ascii //weight: 1
        $x_1_21 = "rstrui.exe" ascii //weight: 1
        $x_1_22 = "systema.exe" ascii //weight: 1
        $x_1_23 = "winamps.exe" ascii //weight: 1
        $x_1_24 = "safemode.exe" ascii //weight: 1
        $x_1_25 = "svchost.exe" ascii //weight: 1
        $x_1_26 = "Restore" ascii //weight: 1
        $x_1_27 = "mmsgs" ascii //weight: 1
        $x_1_28 = "JOIN #" ascii //weight: 1
        $x_1_29 = "NICK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 20 of ($x_1_*))) or
            ((2 of ($x_2_*) and 18 of ($x_1_*))) or
            ((3 of ($x_2_*) and 16 of ($x_1_*))) or
            ((4 of ($x_2_*) and 14 of ($x_1_*))) or
            ((5 of ($x_2_*) and 12 of ($x_1_*))) or
            ((6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((9 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

