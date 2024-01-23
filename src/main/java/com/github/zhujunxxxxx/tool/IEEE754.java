package com.github.zhujunxxxxx.tool;

import com.github.zhujunxxxxx.packet.PacketByte;

import java.util.Arrays;
import java.util.List;

public class IEEE754 {
	
	/**
	 * ����IEEE754Э��תΪdouble,java���Ѿ�ʵ��
	 * @param list
	 * @return
	 */
	public static double byteToDouble(List<PacketByte> list){
		StringBuilder hex=new StringBuilder();
		List<PacketByte> little=PacketByteTool.bigEndianToLittleEndian(list);
		for (int i = 0; i < little.size(); i++) {
			hex.append(little.get(i).getValue());
		}
		Double value=Double.longBitsToDouble(Long.valueOf(hex.toString(), 16));
		return value;
	}
	public static double byteToDouble(PacketByte[] array){
		List<PacketByte> list=Arrays.asList(array);
		return byteToDouble(list);
	}
	
	/***
	 * ����IEEE754תΪfloat
	 * @param list
	 * @return
	 */
	public static float byteToFloat(List<PacketByte> list){
		StringBuilder hex=new StringBuilder();
		List<PacketByte> little=PacketByteTool.bigEndianToLittleEndian(list);
		for (int i = 0; i < little.size(); i++) {
			hex.append(little.get(i).getValue());
		}
		long intValue=Long.valueOf(hex.toString(),16);
		Float value=Float.intBitsToFloat((int)intValue);
		return value;
	}
	public static float byteToFloat(PacketByte[] array){
		List<PacketByte> list=Arrays.asList(array);
		return byteToFloat(list);
	}
	
	/**
	 * 16����תlong
	 * @param list
	 * @return
	 */
	public static long byteToLong(List<PacketByte> list){
		StringBuilder hex=new StringBuilder();
		List<PacketByte> little=PacketByteTool.bigEndianToLittleEndian(list);
		for (int i = 0; i < little.size(); i++) {
			hex.append(little.get(i).getValue());
		}
		return Long.valueOf(hex.toString(),16);
	}
	
	public static long byteToLong(PacketByte[] array){
		List<PacketByte> list=Arrays.asList(array);
		return byteToLong(list);
	}
	
	/**
	 * 16����תint
	 * @param list
	 * @return
	 */
	public static long byteToInt(List<PacketByte> list){
		StringBuilder hex=new StringBuilder();
		List<PacketByte> little=PacketByteTool.bigEndianToLittleEndian(list);
		for (int i = 0; i < little.size(); i++) {
			hex.append(little.get(i).getValue());
		}
		return Integer.valueOf(hex.toString(),16);
	}
	
	public static long byteToInt(PacketByte[] array){
		List<PacketByte> list=Arrays.asList(array);
		return byteToInt(list);
	}
	
	/**
	 * 16����תΪASCII
	 * @param list
	 * @return
	 */
	public static String byteToString(List<PacketByte> list){
		StringBuilder hex=new StringBuilder();
		List<PacketByte> little=PacketByteTool.bigEndianToLittleEndian(list);
		for (int i = 0; i < little.size(); i++) {
			hex.append(little.get(i).getValue());
		}
		String ascii=PacketByteTool.hexToString(hex.toString());
		return ascii;
	}
	
	public static String byteToString(PacketByte[] array){
		List<PacketByte> list=Arrays.asList(array);
		return byteToString(list);
	}
}