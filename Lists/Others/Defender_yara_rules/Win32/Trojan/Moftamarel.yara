rule Trojan_Win32_Moftamarel_B_2147805722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Moftamarel.B"
        threat_id = "2147805722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Moftamarel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "($folder.items | Select-Object -ExpandProperty Body | Select-String \\\"password\\\") -replace '\\s+', ' ' -join ';';\"" ascii //weight: 4
        $x_4_2 = "getEmailAddresses" ascii //weight: 4
        $x_4_3 = "getCredentials" ascii //weight: 4
        $x_2_4 = "powershell -Command \"Start-Process -FilePath \\\"outlook\\\"; Start-Sleep -s 5;\"" ascii //weight: 2
        $x_2_5 = "powershell -Command \"$outlook = Get-Process outlook -ErrorAction SilentlyContinue;" ascii //weight: 2
        $x_1_6 = "Unable to start pipe" ascii //weight: 1
        $x_1_7 = "?startOutlook@@YAHXZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

