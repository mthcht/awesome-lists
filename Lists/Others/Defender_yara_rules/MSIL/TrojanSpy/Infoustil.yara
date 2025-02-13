rule TrojanSpy_MSIL_Infoustil_A_2147708922_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Infoustil.A"
        threat_id = "2147708922"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Infoustil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiCodes" ascii //weight: 1
        $x_1_2 = "BaixaArquivoEExecuta" ascii //weight: 1
        $x_1_3 = "Diretorio" ascii //weight: 1
        $x_1_4 = "DownloadDll" ascii //weight: 1
        $x_1_5 = "MatouProcesso" ascii //weight: 1
        $x_1_6 = "UploadFileLog" ascii //weight: 1
        $x_1_7 = "/js/remoteview/" wide //weight: 1
        $x_1_8 = "netsh wlan show networks mode=bssid" wide //weight: 1
        $x_1_9 = "index.php?action=delete&arquivo=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_MSIL_Infoustil_A_2147708922_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Infoustil.A"
        threat_id = "2147708922"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Infoustil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Executou_WebCam|" wide //weight: 1
        $x_1_2 = "Executando Method|" wide //weight: 1
        $x_1_3 = "Atualizando DLLs|" wide //weight: 1
        $x_1_4 = "Executou_Batch_Texto|" wide //weight: 1
        $x_1_5 = "FileManagerPortableDevice|" wide //weight: 1
        $x_1_6 = "Remote View Parado|" wide //weight: 1
        $x_1_7 = "UploadFTP|" wide //weight: 1
        $x_1_8 = "Uploading Imagem ...|" wide //weight: 1
        $x_1_9 = "Tentando Reiniciar Server|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

