一、笔记
1.匹配transaction的规则:
	对于请求消息：收到的消息和已存在的transactions中的transaction相比较，
	              topvia的brach、host和port字段、CSeq的Method字段都相等，则认为是同一个transaction
	对于回复消息：收到的消息和transactions中的transaction相比较，topvia的
	              branch、CSeq的Method字段都相等，则认为是同一个transaction
	详见:osip_transaction_find
	
2.回复invite 200OK的ACK的via branch和invite的via branch branch不相同
  Cancel的via branch和invite的via branch相同
  
3.invite消息没有to tag，180ring就会携带to tag了
  发出invite时，不会初始化eXosip_dialog_t。收到180ring时，初始化eXosip_dialog_t。
  
4.匹配dialog(会话)的规则:
  4.1UAS的匹配规则(osip_dialog_match_as_uas)  ==>主要是匹配callid和from tag(remote tag)
  1.先匹配callid
  2.再匹配from/to tag，匹配规则如下
      1)如果收到的消息没有from/to tag，匹配失败
	  2)已存在的dialog中没有remote tag，使用收到的消息的from/to头域中的from_uri/to_uri和
	    dialog的remote_uri/local_uri比较，相等则匹配成功，否则失败
	  3)收到的消息有from tag且dialog有remot tag，用from tag和remote tag相匹配，相等则匹配成功，否则失败。
  
  
二、RFC3261:
	还没看  2018.10.31
	
	
三、主要数据结构：
	  struct osip_dialog {
		char *call_id;         /**< Call-ID*/
		char *local_tag;       /**< local tag */ //对uas,是to tag. 对uac,是from tag
		char *remote_tag;      /**< remote tag */ //对uas，是from tag. 对uac，是to tag
		char *line_param;      /**< line param from request uri for incoming calls */
		osip_list_t route_set;         /**< route set */
		int local_cseq;                /**< last local cseq */
		int remote_cseq;               /**< last remote cseq*/
		osip_to_t *remote_uri;         /**< remote_uri */ //对uas，是from tag. 对uac,是to tag
		osip_from_t *local_uri;        /**< local_uri */  //与remote_uri相反
		osip_contact_t *remote_contact_uri;
									   /**< remote contact_uri */
		int secure;                    /**< use secure transport layer */

		osip_dialog_type_t type;       /**< type of dialog (CALLEE or CALLER) */
		state_t state;                 /**< DIALOG_EARLY || DIALOG_CONFIRMED || DIALOG_CLOSED */
		void *your_instance;           /**< for application data reference */
  };
  
     struct eXosip_dialog_t {
		int d_id;
		osip_dialog_t *d_dialog;    /* active dialog */

		time_t d_session_timer_start;       /* session-timer helper */
		int d_session_timer_length;
		int d_refresher;
		int d_session_timer_use_update;

		time_t d_timer;
		int d_count;
		osip_message_t *d_200Ok;
		osip_message_t *d_ack;

		osip_list_t *d_inc_trs; //在会话内收到下述消息，会设置d_inc_trs。==>bye,cancel,reinvite,subscribe,notify,message
		osip_list_t *d_out_trs; //发送会话内的非invite消息时，会设置d_out_trs
		int d_retry;                /* avoid too many unsuccessful retry */
		int d_mincseq;              /* remember cseq after PRACK and UPDATE during setup */

		eXosip_dialog_t *next;
		eXosip_dialog_t *parent;
  };
  
    struct eXosip_call_t {
		int c_id; //上行会话和下行会话 会初始化两个eXosip_call_t，各有要给c_id
		eXosip_dialog_t *c_dialogs; //上行:收到invite，下行:收到180ring的时候，会使用invite或180消息初始化一个
										//eXosip_dialog_t，放入c_dialogs。主要是初始化eXosip_dialog_t->d_dialog
										//eXosip_dialog_t->d_inc_trs/d_out_trs没有赋值，只分配了一块空间
										
		osip_transaction_t *c_inc_tr;  //收到invite时，将invite transaction存在c_inc_tr
		osip_transaction_t *c_out_tr;  //发invite或notify时,会将out transaction赋给c_out_tr
		int c_retry;                /* avoid too many unsuccessful retry */
		void *external_reference;

		time_t expire_time;

		eXosip_call_t *next;
		eXosip_call_t *parent;
  };
  
  
 四、主要函数说明

//先读消息，读到或超时未读到就接着执行下面的状态机函数，效率不高
//可以把读消息和状态机执行函数分开，m个线程专门读(这些线程不需要eXosip_t)。
//n个线程专门调用状态机执行函数(这n个线程可以一个自己的eXosip_t，一共n个)
//m个读线程根据sip消息的from、to头域做hash，得到eXosip_t[i]，以此确定通知
//哪一个状态机处理线程处理相应的状态
int eXosip_execute (struct eXosip_t *excontext)