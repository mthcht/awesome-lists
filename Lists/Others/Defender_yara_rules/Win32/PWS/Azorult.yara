rule PWS_Win32_Azorult_V_2147749118_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Azorult.V!MTB"
        threat_id = "2147749118"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 01 46 3b f7 7c 0b 00 8b 45 ?? 8d 0c 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Azorult_GG_2147776490_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Azorult.GG!MTB"
        threat_id = "2147776490"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Telegram" ascii //weight: 1
        $x_1_2 = "Coins" ascii //weight: 1
        $x_1_3 = "Monero" ascii //weight: 1
        $x_1_4 = "PasswordsList" ascii //weight: 1
        $x_1_5 = "MachineID" ascii //weight: 1
        $x_1_6 = "EXE_PATH" ascii //weight: 1
        $x_1_7 = "Screen:" ascii //weight: 1
        $x_1_8 = "ScreenShot" ascii //weight: 1
        $x_1_9 = "\\Config\\*.vdf" ascii //weight: 1
        $x_1_10 = ".keys" ascii //weight: 1
        $x_1_11 = "\\.purple\\accounts.xml" ascii //weight: 1
        $x_1_12 = "SELECT DATETIME(moz_historyvisits.visit_date/1000000, \"unixepoch\", \"localtime\")," ascii //weight: 1
        $x_1_13 = "moz_places.title,moz_places.url FROM moz_places," ascii //weight: 1
        $x_1_14 = "SELECT DATETIME( ((visits.visit_time/1000000)-11644473600),\"unixepoch\") , urls.title , urls.url FROM urls, visits WHERE urls.id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

