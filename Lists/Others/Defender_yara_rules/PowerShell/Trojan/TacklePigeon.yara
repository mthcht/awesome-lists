rule Trojan_PowerShell_TacklePigeon_A_2147950820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/TacklePigeon.A"
        threat_id = "2147950820"
        type = "Trojan"
        platform = "PowerShell: "
        family = "TacklePigeon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "-Recurse -Include *.doc,*.docx,*.xlsx,*.ppt,*.pptx,*.xls" wide //weight: 5
        $x_5_2 = "New-Object System.Net.WebClient;$wc.UploadFile($uploadUrl, \"PUT\", $file)" wide //weight: 5
        $x_1_3 = "Write-Host \"upload $file to $uploadUrl\"" wide //weight: 1
        $x_1_4 = "Write-Host \"upload Sucess $fileName\"" wide //weight: 1
        $x_1_5 = "Write-Host \"upload $fileName retry $retryCount error: $_\"" wide //weight: 1
        $x_1_6 = "Write-Host \"Drive $drive is not accessible.\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

