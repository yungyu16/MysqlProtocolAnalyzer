package com.github.zhujunxxxxx.tool;

import com.github.zhujunxxxxx.packet.MySqlCommandPacket;
import com.github.zhujunxxxxx.packet.MySqlCommandPreparedPacket;
import com.github.zhujunxxxxx.packet.MySqlCommandQueryPacket;
import com.github.zhujunxxxxx.packet.MySqlExecuteStmtPacket;
import com.github.zhujunxxxxx.packet.MySqlOkPacket;
import com.github.zhujunxxxxx.packet.MySqlPacket;
import com.github.zhujunxxxxx.packet.MySqlPreparedOkPacket;
import com.github.zhujunxxxxx.packet.PacketByte;
import com.github.zhujunxxxxx.packet.TcpPacket;
import com.github.zhujunxxxxx.packet.TransactionGroup;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public class PacketAnalyzer extends TcpDumpFileReader {

	//tcpdump �ļ�������
	private TcpDumpFileHelper helper;
	//MySql packet������
	private PacketBuilder builder;
	private List<MySqlPacket> packetList;
	private List<MySqlPacket> commitOkPacket;//��������commit���ش���־�ŵ�ok��
	private Map<String, ArrayList<MySqlPacket>> groupMap;//����ip_port����İ���������֤ÿ��ip_port��Ӧ���ǰ���ʱ�������
	private List<TransactionGroup> transactionList;//����������б�(ps:�����)
	private String serverIPPort;
	private int lastLogID;
	@Override
	protected void init()
	{
		if(getFileName()==null)
			throw new NullPointerException("fileName");
		if(serverIPPort==null)
			throw new NullPointerException("serverIPPort");
		helper=ToolFactory.getHelperInstance(serverIPPort);
		builder=ToolFactory.getBuilderInstance();
		commitOkPacket=new ArrayList<MySqlPacket>();
		packetList=new ArrayList<MySqlPacket>();
		groupMap=new HashMap<String, ArrayList<MySqlPacket>>();
		transactionList=new ArrayList<TransactionGroup>();
	}
	private void logger(String log)
	{
		System.out.println("[INFO]:"+log);
	}
	private void error(String log)
	{
		System.out.println("[ERROR]:"+log);
	}
	private TcpPacket tcp;
	private MySqlPacket packet;
	private long processSize=0;
	private int oldPercent=0;
	private long begin=0;
	private long end=0;
	@Override
	public void fetchLine(String line) {
		if(helper==null || builder==null){
			throw new NullPointerException("not set TcpDumpFileHelper.");
		}
		tcp=helper.resolveTcpPacket(line);
		if(tcp!=null)
			processTcpPacket(tcp);
		
		processSize+=line.getBytes().length+1;//ûһ������һ������
		int percent=(int) (((float)processSize/getFileSize())*100);
		if(percent!=oldPercent)
		{
			oldPercent=percent;
			System.out.print("\r");
			System.out.print("resolve percent "+makeProcessBar(percent)+percent+"%");
		}
	}
	
	private void processTcpPacket(TcpPacket tcp)
	{
		if(tcp==null)
			throw new NullPointerException("tcp");
		try {
			packet=builder.resolvePacket(tcp);
			if(packet!=null){
				//System.out.println(packet.getClass().getSimpleName());
				packetList.add(packet);
				
				//�����
				if(packet instanceof MySqlOkPacket)
				{
					MySqlOkPacket ok=(MySqlOkPacket)packet;
					if(ok.getMessage()!=null&&ok.getMessage().length>0&&PacketByteTool.hexToString(ok.getMessage()).contains("$logIDMap begin:"))
						commitOkPacket.add(packet);
				}
				
				String key=TcpDumpFileHelper.processHeader(packet.getInfo()).get("ip");
				if(groupMap.containsKey(key))
				{
					groupMap.get(key).add(packet);
				}
				else
				{
					groupMap.put(key, new ArrayList<MySqlPacket>());
					groupMap.get(key).add(packet);
				}
				
			}
		} catch (RuntimeException e) {
			//TODO ignore this exception
			//e.printStackTrace();
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
	}
	
	/**
	 * fetchLine ����ִ��ʱ�����õĺ���
	 */
	@Override
	public void fetchComplete() {
		//�������һ����������
		tcp=helper.resolveLastPacket();
		if(tcp!=null)
			processTcpPacket(tcp);
		
		end=System.currentTimeMillis();
		System.out.println();
		logger("resolve complete!(use time "+(float)(end-begin)/1000+" s)");
		
		writeGroup(groupMap);
		
		if(commitLogSequenceCheck(commitOkPacket))
		{
			logger("file valid!");
			
			begin=System.currentTimeMillis();
			logger("start split group packet to transaction...");
			//����Ϊ������Ϊ��λ�����˵�û���õ����ݰ�
			transactionList=split2Transaction(groupMap);
			end=System.currentTimeMillis();
			logger("split group packet to transaction complete!(use time "+(float)(end-begin)+" ms)");
			//�ع����񣬹��˵�û��Ӱ��������Լ���ѯ���
			
			begin=System.currentTimeMillis();
			logger("start rebuild transaction...");
			transactionList=rebuildTransaction(transactionList);
			end=System.currentTimeMillis();
			logger("rebuild transaction complete!(use time "+(float)(end-begin)+" ms)");
			
			//����commit LogId ����
			begin=System.currentTimeMillis();
			logger("start sort transaction...");
			TransactionGroup[] sortTransaction=sort(transactionList);
			end=System.currentTimeMillis();
			logger("sort transaction complete!(use time "+(float)(end-begin)+" ms)");
			
			//�����ɻָ���sql
			begin=System.currentTimeMillis();
			logger("start build recover sql...");
			buildRecoverSql(sortTransaction,lastLogID);
			end=System.currentTimeMillis();
			logger("build recover sql complete!(use time "+(float)(end-begin)+" ms)");
		}
		else
		{
			error("file invalid!");
		}
	}
	
	/**
	 * ��־˳����
	 * @param commitOK
	 * @return
	 */
	public boolean commitLogSequenceCheck(List<MySqlPacket> commitOK)
	{
		String lastNowLog="";
		String lastLog="";
		for (int i = 0; i < commitOkPacket.size(); i++) {
			MySqlOkPacket ok=(MySqlOkPacket)commitOkPacket.get(i);
			String idPair=PacketByteTool.hexToString(ok.getMessage());
			idPair=idPair.substring("!$logIDMap begin:<".length());
			idPair=idPair.substring(0,idPair.length()-1);
			String[] ids=idPair.split(",");
			lastLog=ids[0];
			if(i!=0)
			{
				if(!lastLog.equals(lastNowLog))
				{
					System.out.println("last:"+lastNowLog +" this log:"+lastLog);
					return false;
				}
				else
				{
					lastNowLog=ids[1];
				}
			}
			else
			{
				lastNowLog=ids[1];
			}
		}
		return true;
	}

	/**
	 * �Ѱ���ip_port�����packetд���ļ�����ȥ
	 * @param group
	 */
	public void writeGroup(Map<String, ArrayList<MySqlPacket>> groups)
	{
		for (Entry<String, ArrayList<MySqlPacket>> group : groups.entrySet()) {
			BufferedWriter bw=null;
			Map<String,String> map=new HashMap<String,String>();
			try {
				bw=new BufferedWriter(new FileWriter(new File(group.getKey())));
				logger("create file:"+group.getKey());
				for (int i = 0; i < group.getValue().size(); i++) {
					
					MySqlPacket p=group.getValue().get(i);
					if(p instanceof MySqlCommandPacket)
					{
						MySqlCommandPacket command=(MySqlCommandPacket)p;
						
						if(command.getCommand().getValue().equals(MySqlCommandPacket.COM_STMT_PREPARE))
						{
							MySqlCommandPreparedPacket prepare=(MySqlCommandPreparedPacket)command;
							bw.write(TcpDumpFileHelper.getTime(p.getInfo())+" COM_STMT_PREPARE:"+PacketByteTool.hexToString(prepare.getArg()));
							bw.write("\n");
						}
						else if(command.getCommand().getValue().equals(MySqlCommandPacket.COM_QUERY))
						{
							MySqlCommandQueryPacket query=(MySqlCommandQueryPacket)command;
							bw.write(TcpDumpFileHelper.getTime(p.getInfo())+" COM_STMT_QUERY:"+PacketByteTool.hexToString(query.getArg()));
							bw.write("\n");
						}
						else
						{
							bw.write(TcpDumpFileHelper.getTime(p.getInfo())+" unkown command packet:"+command.getCommand().getValue());
							bw.write("\n");
						}
					}
					else if(p instanceof MySqlOkPacket)
					{
						MySqlOkPacket ok=(MySqlOkPacket)p;
						
						//����־�ŵ�message
						if(ok.getMessage()!=null&&ok.getMessage().length>0)
						{
							bw.write(TcpDumpFileHelper.getTime(p.getInfo())+" Log ID:"+PacketByteTool.hexToString(ok.getMessage()));
							bw.write("\n");
						}
						else
						{
							bw.write(TcpDumpFileHelper.getTime(p.getInfo())+" Log ID: empty!");
							bw.write("\n");
						}
					}
					else if(p instanceof MySqlPreparedOkPacket)
					{
						MySqlPreparedOkPacket ok=(MySqlPreparedOkPacket)p;
						
						String stmt_id=PacketByte.valueOf(ok.getStatement_id());
						//��ȡ��һ��command����sql
						if(group.getValue().get(i-1) instanceof MySqlCommandPacket)
						{
							MySqlCommandPacket command=(MySqlCommandPacket)group.getValue().get(i-1);
							if(command.getCommand().getValue().equals(MySqlCommandPacket.COM_STMT_PREPARE))//��һ��Ӧ����prepare���
							{
								MySqlCommandPreparedPacket prepare=(MySqlCommandPreparedPacket)command;
								map.put(stmt_id, PacketByteTool.hexToString(prepare.getArg()));
								//bw.write(getTime(p.getInfo())+" PREPARE_STMT_ID:"+stmt_id+" COM_STMT_PREPARE:"+PacketBuilder.hexToString(command.getArg()));
								bw.write(TcpDumpFileHelper.getTime(p.getInfo())+" PREPARE_STMT_ID:"+stmt_id);
								bw.write("\n");
							}
						}
						else
						{
							bw.write(TcpDumpFileHelper.getTime(p.getInfo())+" PREPARE_STMT_ID:"+stmt_id+" ERROR:last packet is "+group.getValue().get(i-1).getClass().getSimpleName());
							bw.write("\n");
						}
					}
					else if(p instanceof MySqlExecuteStmtPacket)
					{
						MySqlExecuteStmtPacket execute=(MySqlExecuteStmtPacket)p;
						
						
						String stmt_id=PacketByte.valueOf(execute.getStmt_id());
						
						if(map.containsKey(stmt_id))
						{
							bw.write(TcpDumpFileHelper.getTime(p.getInfo())+" EXECUTE_STMT_ID:"+stmt_id+" PARAMS TYPE:");
							for (int j = 0; j < execute.getTypes().size(); j++) {
								String typeName=MySqlExecuteStmtPacket.typeName(execute.getTypes().get(j)[0]);
								bw.write(typeName);
								if(j!=execute.getTypes().size()-1)
									bw.write(",");
							}
							bw.write(" PARAMS VALUES:");
							for (int j = 0; j < execute.getValues().size(); j++) {
								String value=PacketByte.valueOf(execute.getValues().get(j));
								bw.write(value);
								if(j!=execute.getValues().size()-1)
									bw.write(",");
							}
							bw.write("\n");
						}
						else
						{
							bw.write(TcpDumpFileHelper.getTime(p.getInfo())+" EXECUTE_STMT_ID:"+stmt_id+" not found this statement id.");
							bw.write("\n");
						}
					}
					else
					{
						bw.write(TcpDumpFileHelper.getTime(p.getInfo())+" OTHER PACKET��"+p.getClass().getName());
						bw.write("\n");
					}
					
				}
				bw.flush();
				bw.close();
			} catch (Exception e) {
				// TODO: handle exception
			}
		}
	}
	/**
	 * ����ip_port�Ѷ�Ӧ��packet����transaction����,���ҹ��˵���Щû�õ����ݰ�(e.g. resultset,error,select��)
	 * @param group
	 */
	public List<TransactionGroup> split2Transaction(Map<String, ArrayList<MySqlPacket>> groups) 
	{
		List<TransactionGroup> transList=new ArrayList<TransactionGroup>();
		for (Entry<String, ArrayList<MySqlPacket>> group : groups.entrySet()) {
			Map<String,String> map=new HashMap<String,String>();
			TransactionGroup tran=null;
			try {
				boolean isComplete=false;
				for (int i = 0; i < group.getValue().size(); i++) {
					if(tran==null)
						tran=new TransactionGroup();
					MySqlPacket p=group.getValue().get(i);

					if(p instanceof MySqlCommandPacket)
					{
						MySqlCommandPacket command=(MySqlCommandPacket)p;
						
						if(command.getCommand().getValue().equals(MySqlCommandPacket.COM_QUERY))//query
						{
							MySqlCommandQueryPacket query=(MySqlCommandQueryPacket)command;
							//commit ���,˵��һ�������ύ
							if(PacketByteTool.hexToString(query.getArg()).equals("commit"))
							{
								isComplete=true;
							}
							else
							{
								//TODO Ҫ���˵�һЩselect���
								tran.addPacket(p);
							}
						}
						else
						{
							//TODO prepare statement������
						}
					}
					else if(p instanceof MySqlOkPacket)
					{
						if(isComplete)
						{
							MySqlOkPacket ok=(MySqlOkPacket)p;
							//����־�ŵ�message
							if(ok.getMessage()!=null&&ok.getMessage().length>0&&PacketByteTool.hexToString(ok.getMessage()).contains("$logIDMap begin:"))
							{
								tran.setLogID(PacketByteTool.hexToString(ok.getMessage()));
								tran.setNoAffect(false);
								transList.add(tran);
								tran=null;
								isComplete=false;
							}
							else//�������ok packet ����ȴû��commitLogID �Ļ�˵���������û��Ӱ��
							{
								tran.setNoAffect(true);
								transList.add(tran);
								tran=null;
								isComplete=false;
							}
						}
						else
						{
							//TODO ok packet����Ҫ������Ϊ�˵��ԣ��ȼӽ���
							tran.addPacket(p);
						}
					}
					else if(p instanceof MySqlPreparedOkPacket)
					{
						MySqlPreparedOkPacket ok=(MySqlPreparedOkPacket)p;
						String stmt_id=PacketByte.valueOf(ok.getStatement_id());
						//��ȡ��һ��command����sql
						if(group.getValue().get(i-1) instanceof MySqlCommandPacket)
						{
							MySqlCommandPacket command=(MySqlCommandPacket)group.getValue().get(i-1);
							if(command.getCommand().getValue().equals(MySqlCommandPacket.COM_STMT_PREPARE))//��һ��Ӧ����prepare���
							{
								MySqlCommandPreparedPacket prepare=(MySqlCommandPreparedPacket)command;
								map.put(stmt_id, PacketByteTool.hexToString(prepare.getArg()));
							}
							else
							{
								//TODO ��һ����䲻��prepare��䣬���˳�������
							}
						}
						else
						{
							//TODO error handle
						}
					}
					else if(p instanceof MySqlExecuteStmtPacket)
					{
						MySqlExecuteStmtPacket execute=(MySqlExecuteStmtPacket)p;
						String stmt_id=PacketByte.valueOf(execute.getStmt_id());
						if(map.containsKey(stmt_id))
						{
							String prepareSql=map.get(stmt_id);
							execute.setStatement(prepareSql);
						}
						if(isComplete)//Ӧ�ò����������֧����Ϊ����ʲôʱ��commit��϶���һ��ok packet
						{
							tran.addPacket(execute);
							transList.add(tran);
							tran=null;
							isComplete=false;
						}
						else
						{
							tran.addPacket(execute);
						}
					}
					else
					{
						//TODO ������DDL������ǲ��ã�����resultSet��
						//System.out.println(p.getClass().getName());
					}
					
				}
			} catch (Exception e) {
				// TODO: handle exception
				e.printStackTrace();
			}
		}
		return transList;
	}
	
	/**
	 * ������־��ID���кϲ�����
	 * @param list
	 */
	public List<TransactionGroup> rebuildTransaction(List<TransactionGroup> list)
	{
		//���¹���
		List<TransactionGroup> transactionList=new ArrayList<TransactionGroup>();
		try {
			for (int i = 0; i < list.size(); i++) {
				
				//�ع�һ��transaction
				TransactionGroup newtran=new TransactionGroup();
				TransactionGroup g=list.get(i);
				if(g.isNoAffect())//û��Ӱ���У��Ͳ���Ҫ����
					continue;
				for (int j = 0; j < g.getList().size(); j++) {
					
					MySqlPacket p=g.getList().get(j);
					
					if(p instanceof MySqlCommandPacket)//�����Ѿ����˺õ�query���͵�command
					{
						MySqlCommandQueryPacket query=(MySqlCommandQueryPacket)p;
						String sql=PacketByteTool.hexToString(query.getArg());
						SQLType stype=getStatementType(sql);
						if(stype==SQLType.INSERT||stype==SQLType.DELETE||stype==SQLType.UPDATE||stype==SQLType.REPALCE)
						{
							newtran.addPacket(p);
						}
						else
						{
							//TODO ��ͨquery��䣬�����������ɲ���
						}
					}
					else if(p instanceof MySqlExecuteStmtPacket)
					{
						MySqlExecuteStmtPacket execute=(MySqlExecuteStmtPacket)p;
						SQLType stype=getStatementType(execute.getStatement());
						if(stype==SQLType.INSERT||stype==SQLType.DELETE||stype==SQLType.UPDATE||stype==SQLType.REPALCE)
						{
							newtran.addPacket(p);
						}
						else if(stype==SQLType.DROP||stype==SQLType.CREATE||stype==SQLType.SELECT||stype==SQLType.UNKNOW)
						{
							//TODO û��Ӱ�����䶪��
						}
					}
					else if(p instanceof MySqlOkPacket)
					{
						//TODO OK packet����
					}
					else
					{
						//TODO ������������֧
						throw new RuntimeException("did'nt come here!");
					}
				}
				if(!g.isNoAffect())
				{
					newtran.setLogID(g.getLogID());
				}
				transactionList.add(newtran);
			}
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
		return transactionList;
	}
	
	/**
	 * ������־ID����
	 * @param list
	 * @return
	 */
	public TransactionGroup[] sort(List<TransactionGroup> list)
	{
		boolean exChange=true;
		TransactionGroup[] array=list.toArray(new TransactionGroup[list.size()]);
		TransactionGroup temp=null;
		for (int i = 0; i < array.length-1; i++) {
			exChange=false;
			for (int j = 0; j < array.length-i-1; j++) {
				if(TcpDumpFileHelper.getRigthID(array[j])>TcpDumpFileHelper.getRigthID(array[j+1]))
				{
					temp=array[j];
					array[j]=array[j+1];
					array[j+1]=temp;
					exChange=true;
				}
			}
			if(!exChange)
				break;
		}
		return array;
	}
	
	/**
	 * ���ݺϲ��õ��������ɿ�ִ�е�sql���
	 * @param sortTran
	 */
	public void buildRecoverSql(TransactionGroup[] sortTran)
	{
		BufferedWriter bw=null;
		//���ɻָ���SQL���
		try {
			bw=new BufferedWriter(new FileWriter(new File("recover.sql")));
			for (int i = 0; i < sortTran.length; i++) {
				TransactionGroup g=sortTran[i];
				if(g.isNoAffect())//û��Ӱ���У��Ͳ���Ҫ����
					continue;
				{
					String idPair=g.getLogID();
					idPair=idPair.substring("!$logIDMap begin:<".length());
					idPair=idPair.substring(0,idPair.length()-1);
					String[] ids=idPair.split(",");
					int logID=Integer.parseInt(ids[1]);
					bw.write(String.format("transaction begin[%s]:\n",logID+""));
				}
				for (int j = 0; j < g.getList().size(); j++) {
					
					MySqlPacket p=g.getList().get(j);
					
					if(p instanceof MySqlCommandPacket)//��ͨ��ѯ���
					{
						MySqlCommandQueryPacket query=(MySqlCommandQueryPacket)p;
						
						String sql=PacketByteTool.hexToString(query.getArg());
						
						bw.write(TcpDumpFileHelper.getTime(p.getInfo())+"##COM_STMT_QUERY:"+sql);
						bw.write("\n");
					}
					else if(p instanceof MySqlExecuteStmtPacket)//execute���
					{
						MySqlExecuteStmtPacket execute=(MySqlExecuteStmtPacket)p;
						String stmt_id=PacketByte.valueOf(execute.getStmt_id());
						bw.write(TcpDumpFileHelper.getTime(p.getInfo())+" EXECUTE_STMT_ID:"+stmt_id+"##PARAMS_TYPE:");
						for (int l = 0; l < execute.getTypes().size(); l++) {
							String typeName=MySqlExecuteStmtPacket.typeName(execute.getTypes().get(l)[0]);
							bw.write(typeName);
							if(l!=execute.getTypes().size()-1)
								bw.write(",");
						}
						bw.write("##");
						bw.write("PREAPRE_STMT:"+execute.getStatement());
						bw.write("##");
						bw.write("PARAMS VALUES:");
						for (int l = 0; l < execute.getValues().size(); l++) {
							
							
							String typeName=MySqlExecuteStmtPacket.typeName(execute.getTypes().get(l)[0]);
							String value="";
							if(typeName.equals("MYSQL_TYPE_DOUBLE"))
							{
								value=String.valueOf(IEEE754.byteToDouble(execute.getValues().get(l)));
							}
							else if(typeName.equals("MYSQL_TYPE_FLOAT"))
							{
								try {
									value=String.valueOf(IEEE754.byteToFloat(execute.getValues().get(l)));
								} catch (Exception e) {
									// TODO: handle exception
									System.out.println(execute.getStatement());
									System.out.println(execute.getInfo());
									System.out.println(PacketByte.valueOf(execute.getValues().get(l)));
								}
								
							}
							else if(typeName.equals("MYSQL_TYPE_TINY")||typeName.equals("MYSQL_TYPE_SHORT")||typeName.equals("MYSQL_TYPE_YEAR")||typeName.equals("MYSQL_TYPE_INT24"))
							{
								value=String.valueOf(IEEE754.byteToInt(execute.getValues().get(l)));
							}
							else if(typeName.equals("MYSQL_TYPE_LONGLONG")||typeName.equals("MYSQL_TYPE_LONG"))
							{
								value=String.valueOf(IEEE754.byteToLong(execute.getValues().get(l)));
							}
							else if(typeName.equals("MYSQL_TYPE_STRING")||typeName.equals("MYSQL_TYPE_VARCHAR")||typeName.equals("MYSQL_TYPE_VAR_STRING")||typeName.equals("MYSQL_TYPE_ENUM")||typeName.equals("MYSQL_TYPE_SET")||typeName.equals("MYSQL_TYPE_LONG_BLOB")||typeName.equals("MYSQL_TYPE_MEDIUM_BLOB")||typeName.equals("MYSQL_TYPE_BLOB")||typeName.equals("MYSQL_TYPE_TINY_BLOB")||typeName.equals("MYSQL_TYPE_GEOMETRY")||typeName.equals("MYSQL_TYPE_BIT")||typeName.equals("MYSQL_TYPE_DECIMAL")||typeName.equals("MYSQL_TYPE_NEWDECIMAL"))
							{
								value=IEEE754.byteToString(execute.getValues().get(l));
							}
							else if(typeName.equals("MYSQL_TYPE_DATE")||typeName.equals("MYSQL_TYPE_DATETIME")||typeName.equals("MYSQL_TYPE_TIMESTAMP"))
							{
								//TODO 
							}
							else if(typeName.equals("MYSQL_TYPE_TIME"))
							{
								//TODO
							}
							else
								value=PacketByte.valueOf(execute.getValues().get(l));
							
							bw.write(value);
							if(l!=execute.getValues().size()-1)
								bw.write(",");
						}
						bw.write("\n");
					}
					else
					{
						//TODO error handle(ps ����ִ�е�����)
						throw new RuntimeException("did'nt come here!");
					}
				}
				
				bw.write("transaction end\n");
			}
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}finally {
			try {
				bw.close();
			} catch (Exception e2) {
				// TODO: handle exception
			}
		}
	}
	
	/**
	 * ���ݺϲ��õ��������ɿ�ִ�е�sql���
	 * @param sortTran
	 */
	public void buildRecoverSql(TransactionGroup[] sortTran,int lastCommitLogID)
	{
		BufferedWriter bw=null;
		//���ɻָ���SQL���
		try {
			bw=new BufferedWriter(new FileWriter(new File("recover.sql")));
			for (int i = 0; i < sortTran.length; i++) {
				TransactionGroup g=sortTran[i];
				if(g.isNoAffect())//û��Ӱ���У��Ͳ���Ҫ����
					continue;
				{
					String idPair=g.getLogID();
					idPair=idPair.substring("!$logIDMap begin:<".length());
					idPair=idPair.substring(0,idPair.length()-1);
					String[] ids=idPair.split(",");
					int logID=Integer.parseInt(ids[1]);
					if(logID<=lastCommitLogID){
						continue;
					}
					
					bw.write(String.format("transaction begin[%s]:\n",logID+""));
				}
				for (int j = 0; j < g.getList().size(); j++) {
					
					MySqlPacket p=g.getList().get(j);
					
					if(p instanceof MySqlCommandPacket)//��ͨ��ѯ���
					{
						MySqlCommandQueryPacket query=(MySqlCommandQueryPacket)p;
						
						String sql=PacketByteTool.hexToString(query.getArg());
						
						bw.write(TcpDumpFileHelper.getTime(p.getInfo())+"##COM_STMT_QUERY:"+sql);
						bw.write("\n");
					}
					else if(p instanceof MySqlExecuteStmtPacket)//execute���
					{
						MySqlExecuteStmtPacket execute=(MySqlExecuteStmtPacket)p;
						String stmt_id=PacketByte.valueOf(execute.getStmt_id());
						bw.write(TcpDumpFileHelper.getTime(p.getInfo())+" EXECUTE_STMT_ID:"+stmt_id+"##PARAMS_TYPE:");
						for (int l = 0; l < execute.getTypes().size(); l++) {
							String typeName=MySqlExecuteStmtPacket.typeName(execute.getTypes().get(l)[0]);
							bw.write(typeName);
							if(l!=execute.getTypes().size()-1)
								bw.write(",");
						}
						bw.write("##");
						bw.write("PREAPRE_STMT:"+execute.getStatement());
						bw.write("##");
						bw.write("PARAMS VALUES:");
						for (int l = 0; l < execute.getValues().size(); l++) {
							
							
							String typeName=MySqlExecuteStmtPacket.typeName(execute.getTypes().get(l)[0]);
							String value="";
							if(typeName.equals("MYSQL_TYPE_DOUBLE"))
							{
								value=String.valueOf(IEEE754.byteToDouble(execute.getValues().get(l)));
							}
							else if(typeName.equals("MYSQL_TYPE_FLOAT"))
							{
								try {
									value=String.valueOf(IEEE754.byteToFloat(execute.getValues().get(l)));
								} catch (Exception e) {
									// TODO: handle exception
									System.out.println(execute.getStatement());
									System.out.println(execute.getInfo());
									System.out.println(PacketByte.valueOf(execute.getValues().get(l)));
								}
								
							}
							else if(typeName.equals("MYSQL_TYPE_TINY")||typeName.equals("MYSQL_TYPE_SHORT")||typeName.equals("MYSQL_TYPE_YEAR")||typeName.equals("MYSQL_TYPE_INT24"))
							{
								value=String.valueOf(IEEE754.byteToInt(execute.getValues().get(l)));
							}
							else if(typeName.equals("MYSQL_TYPE_LONGLONG")||typeName.equals("MYSQL_TYPE_LONG"))
							{
								value=String.valueOf(IEEE754.byteToLong(execute.getValues().get(l)));
							}
							else if(typeName.equals("MYSQL_TYPE_STRING")||typeName.equals("MYSQL_TYPE_VARCHAR")||typeName.equals("MYSQL_TYPE_VAR_STRING")||typeName.equals("MYSQL_TYPE_ENUM")||typeName.equals("MYSQL_TYPE_SET")||typeName.equals("MYSQL_TYPE_LONG_BLOB")||typeName.equals("MYSQL_TYPE_MEDIUM_BLOB")||typeName.equals("MYSQL_TYPE_BLOB")||typeName.equals("MYSQL_TYPE_TINY_BLOB")||typeName.equals("MYSQL_TYPE_GEOMETRY")||typeName.equals("MYSQL_TYPE_BIT")||typeName.equals("MYSQL_TYPE_DECIMAL")||typeName.equals("MYSQL_TYPE_NEWDECIMAL"))
							{
								value=IEEE754.byteToString(execute.getValues().get(l));
							}
							else if(typeName.equals("MYSQL_TYPE_DATE")||typeName.equals("MYSQL_TYPE_DATETIME")||typeName.equals("MYSQL_TYPE_TIMESTAMP"))
							{
								//TODO 
							}
							else if(typeName.equals("MYSQL_TYPE_TIME"))
							{
								//TODO
							}
							else
								value=PacketByte.valueOf(execute.getValues().get(l));
							
							bw.write(value);
							if(l!=execute.getValues().size()-1)
								bw.write(",");
						}
						bw.write("\n");
					}
					else
					{
						//TODO error handle(ps ����ִ�е�����)
						throw new RuntimeException("did'nt come here!");
					}
				}
				
				bw.write("transaction end\n");
			}
			bw.close();
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		} finally {
			try {
				bw.close();
			} catch (Exception e2) {
				// TODO: handle exception
			}
		}
	}
	public void setServerIPPort(String serverIPPort) {
		this.serverIPPort = serverIPPort;
	}
	
	public void setLastLogID(int lastLogID) {
		this.lastLogID = lastLogID;
	}

	public static enum SQLType
	{
		SELECT,
		UPDATE,
		REPALCE,
		INSERT,
		DELETE,
		DROP,
		CREATE,
		UNKNOW
	}
	public static SQLType getStatementType(String sql)
	{
		if(sql.toLowerCase().trim().substring(0,6).equals("select"))
			return SQLType.SELECT;
		if(sql.toLowerCase().trim().substring(0,6).equals("insert"))
			return SQLType.INSERT;
		if(sql.toLowerCase().trim().substring(0,6).equals("update"))
			return SQLType.UPDATE;
		if(sql.toLowerCase().trim().substring(0,6).equals("delete"))
			return SQLType.DELETE;
		if(sql.toLowerCase().trim().substring(0,6).equals("create"))
			return SQLType.CREATE;
		if(sql.toLowerCase().trim().substring(0,7).equals("replace"))
			return SQLType.DELETE;
		if(sql.toLowerCase().trim().substring(0,4).equals("drop"))
			return SQLType.DROP;
		return SQLType.UNKNOW;
			
	}
	public static String makeProcessBar(int per)
	{
		StringBuilder bar=new StringBuilder();
		bar.append("[");
		for (int i = 0; i < 100; i++) {
			if(i<per)
				bar.append("=");
			else
				bar.append(" ");
		}
		bar.append("] ");
		return bar.toString();
	}
	@Override
	protected void beforeResolve() {
		// TODO Auto-generated method stub
		logger("file name is :"+getFileName());
		logger("file size is :"+getFileSize()/1000+"KB");
		logger("start resolve....");
		begin=System.currentTimeMillis();
	}

}