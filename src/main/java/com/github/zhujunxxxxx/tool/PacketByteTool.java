package com.github.zhujunxxxxx.tool;

import com.github.zhujunxxxxx.packet.PacketByte;

import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

public class PacketByteTool {
	
	public static PacketByte[] subListToArray(List<PacketByte> list,int pos,int length){
		if (list == null) {
			throw new NullPointerException();
		} else if (pos >= list.size()-1 || pos + length > list.size()) {
			throw new IndexOutOfBoundsException();
		} else {
			PacketByte[] result=new PacketByte[length];
			for (int i = 0; i < result.length; i++) {
				result[i] = list.get(pos + i);
			}
			return result;
		}
	}
	public static PacketByte getListItem(List<PacketByte> list, int pos){
		if (list == null) {
			throw new NullPointerException();
		} else if (pos >= list.size()-1) {
			throw new IndexOutOfBoundsException();
		} else {
			return list.get(pos);
		}
	}
	
	public static List<PacketByte> subList(List<PacketByte> list,int pos,int length){
		if (list == null) {
			throw new NullPointerException();
		} else if (pos >= list.size()-1 || pos + length > list.size()) {
			throw new IndexOutOfBoundsException();
		} else {
			List<PacketByte> result=new ArrayList<PacketByte>();
			for (int i = 0; i < result.size(); i++) {
				result.add(list.get(pos + i));
			}
			return result;
		}
	}
	
	public static List<PacketByte> subArrayList(PacketByte[] array,int pos,int length){
		if (array == null) {
			throw new NullPointerException();
		} else if (pos >= array.length-1 || pos + length > array.length) {
			throw new IndexOutOfBoundsException();
		} else {
			List<PacketByte> result=new ArrayList<PacketByte>();
			for (int i = 0; i < result.size(); i++) {
				result.add(array[pos + i]);
			}
			return result;
		}
	}
	
	public static PacketByte[] subArray(PacketByte[] array,int pos,int length){
		if (array == null) {
			throw new NullPointerException();
		} else if (pos >= array.length-1 || pos + length > array.length) {
			throw new IndexOutOfBoundsException();
		} else {
			PacketByte[] result=new PacketByte[length];
			for (int i = 0; i < result.length; i++) {
				result[i] = array[pos + i];
			}
			return result;
		}
	}
	
	/**
	 * ����С�������10���Ƶ�ֵ
	 * @param array
	 * @return
	 */
	public static int computeLength(PacketByte[] array){
		if(array == null)
			throw new NullPointerException();
		List<PacketByte> reversal=new ArrayList<PacketByte>();
		for (int i = 0; i < array.length; i++) {
			reversal.add(array[i]);
		}
		return ByteToDecimal(reversal);
	}
	
	/**
	 * �����תΪС����
	 * @param list
	 * @return
	 */
	public static List<PacketByte> bigEndianToLittleEndian(List<PacketByte> list){
		if(list == null)
			throw new NullPointerException();
		List<PacketByte> littleEndian=new ArrayList<PacketByte>();
		for (int i = list.size()-1; i >= 0; i--) {
			littleEndian.add(list.get(i));
		}
		return littleEndian;
	}
	
	/***
	 * ��16���Ƶ�תΪ10����
	 * @param array
	 * @return
	 */
	public static int ByteToDecimal(PacketByte[] array){
		if(array == null)
			throw new NullPointerException();
		Stack<Integer> bin=new Stack<Integer>();
		for (int i = 0; i < array.length; i++) {
			bin.push(hexToInt(array[i].getFirst()));
			bin.push(hexToInt(array[i].getSecond()));
		}
		int value=0;
		int level=0;
		while(!bin.empty()){
			int number=bin.pop();
			value = (int) (value + Math.pow(16, level) * number);
			level++;
		}
		return value;
	}
	
	/***
	 * ��16���Ƶ�תΪ10����
	 * @param list
	 * @return
	 */
	public static int ByteToDecimal(List<PacketByte> list){
		if(list == null)
			throw new NullPointerException();
		Stack<Integer> bin=new Stack<Integer>();
		for (int i = 0; i < list.size(); i++) {
			bin.push(hexToInt(list.get(i).getFirst()));
			bin.push(hexToInt(list.get(i).getSecond()));
		}
		int value=0;
		int level=0;
		while(!bin.empty()){
			int number=bin.pop();
			value = (int) (value + Math.pow(16, level) * number);
			level++;
		}
		return value;
	}
	public static int ByteToInteger(PacketByte pb)
	{
		String output=pb.getValue();
		int decimal=Integer.parseInt(output, 16);
		return decimal;
	}
	/***
	 * ��16���Ƶ�תΪ10����
	 * @param pb
	 * @return
	 */
	public static int ByteToDecimal(PacketByte pb){
		if(pb == null)
			throw new NullPointerException();
		Stack<Integer> bin=new Stack<Integer>();
		bin.push(hexToInt(pb.getFirst()));
		bin.push(hexToInt(pb.getSecond()));
		int value=0;
		int level=0;
		while(!bin.empty()){
			int number=bin.pop();
			value = (int) (value + Math.pow(16, level) * number);
			level++;
		}
		return value;
	}
	
	/**
	 * 16�����ַ�תΪ��Ӧʮ��������
	 * @param hex
	 * @return
	 */
	public static int hexToInt(String hex){
		if(!hex.equals("a") && !hex.equals("b") && !hex.equals("c") && !hex.equals("d") && !hex.equals("e") && !hex.equals("f")){
			return Integer.parseInt(hex);
		} else {
			if(hex.equalsIgnoreCase("a"))
				return 10;
			else if(hex.equalsIgnoreCase("b"))
				return 11;
			else if(hex.equalsIgnoreCase("c"))
				return 12;
			else if(hex.equalsIgnoreCase("d"))
				return 13;
			else if(hex.equalsIgnoreCase("e"))
				return 14;
			else if(hex.equalsIgnoreCase("f"))
				return 15;
			else
				throw new IllegalArgumentException();
		}
	}
	/**
	 * 16����תΪASCII
	 * @param hex
	 * @return
	 */
	public static String hexToString(String hex){
		
		StringBuilder sb=new StringBuilder();
		for (int i = 0; i < hex.length()-1; i+=2) {
			String outPut=hex.substring(i,(i+2));
			int decimal=Integer.parseInt(outPut,16);
			sb.append((char)decimal);
		}
		return sb.toString();
	}
	
	/**
	 * 16����תΪASCII
	 * @param array
	 * @return
	 */
	public static String hexToString(PacketByte[] array){
		if(array==null)
			throw new NullPointerException();
		if(array.length==0)
			return "";
		StringBuilder temp=new StringBuilder();
		for (int i = 0; i < array.length; i++) {
			temp.append(array[i].getValue());
		}
		String hex=temp.toString();
		StringBuilder sb=new StringBuilder();
		for (int i = 0; i < hex.length()-1; i+=2) {
			String outPut=hex.substring(i,(i+2));
			int decimal=Integer.parseInt(outPut,16);
			sb.append((char)decimal);
		}
		return sb.toString();
	}
	
	/**
	 * ����LengthEncodedInteger�ĳ��ȵ��ж�
	 * @param pb
	 * @return
	 */
	public static int lengthInt(PacketByte pb){
		if(pb.getValue().equals("fc"))
			return 2;
		else if(pb.getValue().equals("fd"))
			return 3;
		else if(pb.getValue().equals("fe"))
			return 8;
		else
			return 1;
	}
}