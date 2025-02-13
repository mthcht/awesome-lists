rule TrojanClicker_Win32_Spackit_A_2147697451_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Spackit.A"
        threat_id = "2147697451"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Spackit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<clickurl>" ascii //weight: 1
        $x_1_2 = "<cpc>" ascii //weight: 1
        $x_1_3 = "netbid=" ascii //weight: 1
        $x_1_4 = "&sid={aid}&builddate={builddate}&q={keyword}" ascii //weight: 1
        $x_1_5 = "-khb747bjg324yu" wide //weight: 1
        $x_1_6 = "hidden" wide //weight: 1
        $x_1_7 = "Shell DocObject View" wide //weight: 1
        $x_1_8 = "iehardenienowarn" ascii //weight: 1
        $x_1_9 = "warnonpostredirect" ascii //weight: 1
        $x_1_10 = {2e 63 6f 6d 2c [0-16] 2e 63 6f 6d 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Spackit_A_2147697451_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Spackit.A"
        threat_id = "2147697451"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Spackit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<clickurl><![cdata[" ascii //weight: 1
        $x_1_2 = "<uri><![cdata[" ascii //weight: 1
        $x_1_3 = {62 69 64 3d 22 00 00 00 6e 65 74 62 69 64 3d 22}  //weight: 1, accuracy: High
        $x_1_4 = "lower+back+pain" ascii //weight: 1
        $x_1_5 = "compare+car+insurance+rates" ascii //weight: 1
        $x_1_6 = "\\Broadcom CrystalHD Decoder\\bcmDIL.dll" wide //weight: 1
        $x_1_7 = {5c 7a 6f 6e 65 6d 61 70 00 69 65 68 61 72 64 65 6e 69 65 6e 6f 77 61 72 6e}  //weight: 1, accuracy: High
        $x_1_8 = "{server}/feed?version={version}&sid={aid}&q={keyword}&ref={ref}&ua={ua}&lang={lang}" ascii //weight: 1
        $x_1_9 = "{server}/query?version=1.6&sid={aid}&builddate={builddate}&q={keyword}&ua={ua}&lang={lang}&wt={threads}&lr={lastresult}&ls={laststage}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

