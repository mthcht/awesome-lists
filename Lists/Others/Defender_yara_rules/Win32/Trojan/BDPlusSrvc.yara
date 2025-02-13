rule Trojan_Win32_BDPlusSrvc_B_2147794557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BDPlusSrvc.B!dha"
        threat_id = "2147794557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BDPlusSrvc"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Instruction::testInstruction" ascii //weight: 10
        $x_10_2 = "Instruction::tdkdfkvdf" ascii //weight: 10
        $x_10_3 = "Instruction::noCmdInstruction" ascii //weight: 10
        $x_10_4 = "Instruction::deleteCmdInstruction" ascii //weight: 10
        $x_10_5 = "Instruction::downloadExcecutableFileInstruction" ascii //weight: 10
        $x_10_6 = "Instruction::updateRelayInstruction" ascii //weight: 10
        $x_10_7 = "Instruction::updateInterval" ascii //weight: 10
        $x_10_8 = "Instruction::downloadExcecutableUrlInstruction" ascii //weight: 10
        $x_10_9 = "Instruction::cmdExcecuteInstruction" ascii //weight: 10
        $x_10_10 = "Instruction::crcErrorInstrunction" ascii //weight: 10
        $x_10_11 = "Instruction::nodeRegisterInstruction" ascii //weight: 10
        $x_10_12 = "Instruction::failedInstruction" ascii //weight: 10
        $x_10_13 = "Instruction::ackedInstruction" ascii //weight: 10
        $x_10_14 = "Instruction::mergeSystemInfo" ascii //weight: 10
        $x_10_15 = "Functions::testInstruction" ascii //weight: 10
        $x_10_16 = "Functions::eteledDmcInstruction" ascii //weight: 10
        $x_10_17 = "Functions::daolnwodElbatucexeElifInstruction" ascii //weight: 10
        $x_10_18 = "Functions::etadpuYalerInstruction" ascii //weight: 10
        $x_10_19 = "Functions::etadpuLavretniInstruction" ascii //weight: 10
        $x_10_20 = "Functions::daolnwodElbatucexeLruInstruction" ascii //weight: 10
        $x_10_21 = "Functions::dmcEtucecxeInstruction" ascii //weight: 10
        $x_10_22 = "Functions::tegEdonLlufOfniInstruction" ascii //weight: 10
        $x_10_23 = "Functions::crcErrorInstrunction" ascii //weight: 10
        $x_10_24 = "Functions::edonRetisigerInstruction" ascii //weight: 10
        $x_10_25 = "Functions::ackedInstruction" ascii //weight: 10
        $x_10_26 = "Functions::mergeSponsorInfo" ascii //weight: 10
        $x_2_27 = "NODE_REG" ascii //weight: 2
        $x_2_28 = "IS_CMD_AVAIL" ascii //weight: 2
        $x_2_29 = "CMD_EXECUTE" ascii //weight: 2
        $x_2_30 = "DL_EXEC_FILE" ascii //weight: 2
        $x_2_31 = "DL_EXEC_URL" ascii //weight: 2
        $x_2_32 = "DELETE_CMD" ascii //weight: 2
        $x_2_33 = "UPDATE_RELAYS" ascii //weight: 2
        $x_2_34 = "UPDATE_INTERVAL" ascii //weight: 2
        $x_1_35 = "NO_CMD" ascii //weight: 1
        $x_1_36 = "CRC_ERROR" ascii //weight: 1
        $x_1_37 = "\\Uninstall.bat" ascii //weight: 1
        $x_1_38 = "\\config.txt" ascii //weight: 1
        $x_1_39 = "\\node.txt" ascii //weight: 1
        $x_1_40 = "\\result.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

