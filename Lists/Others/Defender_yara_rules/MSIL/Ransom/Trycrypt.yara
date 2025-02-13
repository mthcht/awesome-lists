rule Ransom_MSIL_Trycrypt_2147725254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Trycrypt"
        threat_id = "2147725254"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Trycrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "You have n days to pay otherwise you will lose your files" wide //weight: 5
        $x_5_2 = "ENTER BITCOIN TRANSACTION ID" wide //weight: 5
        $x_5_3 = "projectfun.azurewebsites.net/api/CheckClientPaid" wide //weight: 5
        $x_5_4 = "code=2E484UNKRo6LESYNmhro5v0FhQlauSyoPtOv2j1HE7vCzliXj79sng==" wide //weight: 5
        $x_5_5 = "projectfun.azurewebsites.net/api/GetDecKey" wide //weight: 5
        $x_5_6 = "code=1FiG/QfavLiIN8z6GwKIINgiOUhoJ31X6hc2a44ukyBB4QBw8qPFvw==" wide //weight: 5
        $x_5_7 = "projectfun.azurewebsites.net/api/GetInsertTime" wide //weight: 5
        $x_5_8 = "code=PC/i3vLto84fUa8qMdTHmJa9uLGLaj2eJWa4fFWPiyHcAB2/JQ1Tyw==" wide //weight: 5
        $x_5_9 = "projectfun.azurewebsites.net/api/SetClientPaid" wide //weight: 5
        $x_5_10 = "code=XaAA9i6R27wFXFnotEMTIEXRxJ4KGktVE6eG4Us9NzLoyQcyt2CK6w==" wide //weight: 5
        $x_5_11 = "projectfun.azurewebsites.net/api/SetFinishDecryption" wide //weight: 5
        $x_5_12 = "code=NZ6ZpynCNvtWqq2oFlrlWc3hasdYDhrqJAyIVqVOIQ8t8kAyIWbxaw==" wide //weight: 5
        $x_5_13 = "projectfun.azurewebsites.net/api/CheckIfFinished" wide //weight: 5
        $x_5_14 = "code=vopG5waQwNR7mViKrlrJkaDmegeCYJQVanVBr4ahG1LtBfXKbEIIsA==" wide //weight: 5
        $x_5_15 = "projectfun.azurewebsites.net/api/CreatRsaClient" wide //weight: 5
        $x_5_16 = "code=HtR5uoBGkrrvignZuSPmEvlpCVYWiSTaxVTvnJByJuXourUEzWRU0A==" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

