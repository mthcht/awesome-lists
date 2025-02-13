rule TrojanClicker_Win32_Cookster_A_2147648962_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Cookster.A"
        threat_id = "2147648962"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Cookster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 44 24 30 e8 ?? ?? ff ff 6a 0f 6a 03 89 44 24 4c e8 ?? ?? ff ff 6a 64 6a 28 89 44 24 50 e8 ?? ?? ff ff 6a 0f 6a 03 89 44 24 54 e8 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_1_2 = "%s&ck=%d.%d.%d.%d.%d.%d.%d.%d" ascii //weight: 1
        $x_1_3 = "BD('%s').SearchAndClick('%s');" ascii //weight: 1
        $x_1_4 = "/sentry/api/server.php" ascii //weight: 1
        $x_1_5 = "traffic.getActionListFromHTML" ascii //weight: 1
        $x_1_6 = "Browser().InvokeScript('document.getElementById('%s').onmousedown();');" ascii //weight: 1
        $x_1_7 = "Browser().InvokeScript('document.getElementById('%s').click();');" ascii //weight: 1
        $x_1_8 = "Client().Sleep('5');" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

