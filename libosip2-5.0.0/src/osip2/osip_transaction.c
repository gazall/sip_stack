/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc3261-)
  Copyright (C) 2001-2012 Aymeric MOIZARD amoizard@antisip.com
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <osip2/internal.h>
#include <osip2/osip.h>

#include "fsm.h"
#include "xixt.h"

extern osip_statemachine_t ict_fsm;
extern osip_statemachine_t ist_fsm;
extern osip_statemachine_t nict_fsm;
extern osip_statemachine_t nist_fsm;

int osip_id_mutex_lock (osip_t * osip);
int osip_id_mutex_unlock (osip_t * osip);

static int __osip_transaction_set_topvia (osip_transaction_t * transaction, osip_via_t * topvia);
static int __osip_transaction_set_from (osip_transaction_t * transaction, osip_from_t * from);
static int __osip_transaction_set_to (osip_transaction_t * transaction, osip_to_t * to);
static int __osip_transaction_set_call_id (osip_transaction_t * transaction, osip_call_id_t * call_id);
static int __osip_transaction_set_cseq (osip_transaction_t * transaction, osip_cseq_t * cseq);

static int
__osip_transaction_set_topvia (osip_transaction_t * transaction, osip_via_t * topvia)
{
  int i;

  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  i = osip_via_clone (topvia, &(transaction->topvia));
  if (i == 0)
    return OSIP_SUCCESS;
  transaction->topvia = NULL;
  return i;
}

static int
__osip_transaction_set_from (osip_transaction_t * transaction, osip_from_t * from)
{
  int i;

  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  i = osip_from_clone (from, &(transaction->from));
  if (i == 0)
    return OSIP_SUCCESS;
  transaction->from = NULL;
  return i;
}

static int
__osip_transaction_set_to (osip_transaction_t * transaction, osip_to_t * to)
{
  int i;

  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  i = osip_to_clone (to, &(transaction->to));
  if (i == 0)
    return OSIP_SUCCESS;
  transaction->to = NULL;
  return i;
}

static int
__osip_transaction_set_call_id (osip_transaction_t * transaction, osip_call_id_t * call_id)
{
  int i;

  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  i = osip_call_id_clone (call_id, &(transaction->callid));
  if (i == 0)
    return OSIP_SUCCESS;
  transaction->callid = NULL;
  return i;
}

static int
__osip_transaction_set_cseq (osip_transaction_t * transaction, osip_cseq_t * cseq)
{
  int i;

  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  i = osip_cseq_clone (cseq, &(transaction->cseq));
  if (i == 0)
    return OSIP_SUCCESS;
  transaction->cseq = NULL;
  return i;
}

//1.为transaction分配空间，使用message对transaction的各个成员赋值，
//2.设置transaction对应的消息重传定时器
//3.将transaction插入到osip中对应的事件队列的队尾
int
osip_transaction_init (osip_transaction_t ** transaction, osip_fsm_type_t ctx_type, osip_t * osip, osip_message_t * request)
{
  osip_via_t *topvia;

  int i;

  *transaction = NULL;
  if (request == NULL)
    return OSIP_BADPARAMETER;
  if (request->call_id == NULL)
    return OSIP_BADPARAMETER;
  if (request->call_id->number == NULL)
    return OSIP_BADPARAMETER;

  *transaction = (osip_transaction_t *) osip_malloc (sizeof (osip_transaction_t));
  if (*transaction == NULL)
    return OSIP_NOMEM;

  memset (*transaction, 0, sizeof (osip_transaction_t));

  (*transaction)->birth_time = osip_getsystemtime (NULL);

  osip_id_mutex_lock (osip);
  (*transaction)->transactionid = osip->transactionid++;
  osip_id_mutex_unlock (osip);
  OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_INFO2, NULL, "allocating transaction resource %i %s\n", (*transaction)->transactionid, request->call_id->number));

  /* those lines must be called before "osip_transaction_free" */
  (*transaction)->ctx_type = ctx_type;
  (*transaction)->ict_context = NULL;
  (*transaction)->ist_context = NULL;
  (*transaction)->nict_context = NULL;
  (*transaction)->nist_context = NULL;
  (*transaction)->config = osip;  //osip_transaction_t->config反指向osip_t

  topvia = osip_list_get (&request->vias, 0);
  if (topvia == NULL) {
    osip_transaction_free (*transaction);
    *transaction = NULL;
    return OSIP_SYNTAXERROR;
  }
  i = __osip_transaction_set_topvia (*transaction, topvia);  //将sip消息的topvia保存在osip_transaction_t->topvia
  if (i != 0) {
    osip_transaction_free (*transaction);
    *transaction = NULL;
    return i;
  }

  /* In some situation, some of those informtions might
     be useless. Mostly, I prefer to keep them in all case
     for backward compatibility. */
  i = __osip_transaction_set_from (*transaction, request->from);
  if (i != 0) {
    osip_transaction_free (*transaction);
    *transaction = NULL;
    return i;
  }
  i = __osip_transaction_set_to (*transaction, request->to);
  if (i != 0) {
    osip_transaction_free (*transaction);
    *transaction = NULL;
    return i;
  }
  i = __osip_transaction_set_call_id (*transaction, request->call_id);
  if (i != 0) {
    osip_transaction_free (*transaction);
    *transaction = NULL;
    return i;
  }
  i = __osip_transaction_set_cseq (*transaction, request->cseq);
  if (i != 0) {
    osip_transaction_free (*transaction);
    *transaction = NULL;
    return i;
  }
  /* RACE conditions can happen for server transactions */
  /* (*transaction)->orig_request = request; */
  (*transaction)->orig_request = NULL;

  (*transaction)->transactionff = (osip_fifo_t *) osip_malloc (sizeof (osip_fifo_t));
  if ((*transaction)->transactionff == NULL) {
    osip_transaction_free (*transaction);
    *transaction = NULL;
    return OSIP_NOMEM;
  }
  osip_fifo_init ((*transaction)->transactionff);

  if (ctx_type == ICT) {
    (*transaction)->state = ICT_PRE_CALLING;
	//ict_context用来设置重传定时器，ict有两种定时器
	//对于udp协议，timer_a设置为500ms之后，timer_d在函数__osip_ict_init中还没激活，估计是等到timer_a触发后激活
    i = __osip_ict_init (&((*transaction)->ict_context), osip, request);  
    if (i != 0) {
      osip_transaction_free (*transaction);
      *transaction = NULL;
      return i;
    }
    __osip_add_ict (osip, *transaction);  //将transaction插入osip_t->osip_ict_transactions队列末尾，插入的是指针
  }
  else if (ctx_type == IST) {  
    (*transaction)->state = IST_PRE_PROCEEDING;
    i = __osip_ist_init (&((*transaction)->ist_context), osip, request);
    if (i != 0) {
      osip_transaction_free (*transaction);
      *transaction = NULL;
      return i;
    }
    __osip_add_ist (osip, *transaction);
  }
  else if (ctx_type == NICT) {
    (*transaction)->state = NICT_PRE_TRYING;
    i = __osip_nict_init (&((*transaction)->nict_context), osip, request);
    if (i != 0) {
      osip_transaction_free (*transaction);
      *transaction = NULL;
      return i;
    }
    __osip_add_nict (osip, *transaction);
  }
  else {
    (*transaction)->state = NIST_PRE_TRYING;
    i = __osip_nist_init (&((*transaction)->nist_context), osip, request);
    if (i != 0) {
      osip_transaction_free (*transaction);
      *transaction = NULL;
      return i;
    }
    __osip_add_nist (osip, *transaction);
  }
  //上面所用的__osip_****_init函数的作用都是设置定时器，
  //不同类型的sip消息有不同的定时器
  //一个定时器有两个要素
  //1.timer_*_length : 定时器时长
  //2.timer_*_start : timer_*_start.tv_sec = -1，定时器不触发, >=0，定时器在timer_*_length时间后触发

  
  return OSIP_SUCCESS;
}

/* This method automaticly remove the transaction context from
   the osip stack. This task is required for proper operation
   when a transaction goes in the TERMINATED STATE.
   However the user might want to just take the context out of
   the SIP stack andf keep it for future use without freeing
   all resource.... This way the transaction context can be
   kept without being used by the oSIP stack.

   new methods that replace this one:
   osip_remove_transaction
   +
   osip_transaction_free2();

 */
int
osip_transaction_free (osip_transaction_t * transaction)
{
  int i;

  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  i = osip_remove_transaction (transaction->config, transaction);

  if (i != 0) {                 /* yet removed ??? */
    OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_INFO4, NULL, "transaction already removed from list %i!\n", transaction->transactionid));
  }

  return osip_transaction_free2 (transaction);
}

/* same as osip_transaction_free() but assume the transaction is
   already removed from the list of transaction in the osip stack */
int
osip_transaction_free2 (osip_transaction_t * transaction)
{
  osip_event_t *evt;

  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  if (transaction->orig_request != NULL && transaction->orig_request->call_id != NULL && transaction->orig_request->call_id->number != NULL) {
    OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_INFO2, NULL, "free transaction resource %i %s\n", transaction->transactionid, transaction->orig_request->call_id->number));
  }
  if (transaction->ctx_type == ICT) {
    __osip_ict_free (transaction->ict_context);
  }
  else if (transaction->ctx_type == IST) {
    __osip_ist_free (transaction->ist_context);
  }
  else if (transaction->ctx_type == NICT) {
    __osip_nict_free (transaction->nict_context);
  }
  else {
    __osip_nist_free (transaction->nist_context);
  }

  /* empty the fifo */
  if (transaction->transactionff != NULL) {
    evt = osip_fifo_tryget (transaction->transactionff);
    while (evt != NULL) {
      osip_message_free (evt->sip);
      osip_free (evt);
      evt = osip_fifo_tryget (transaction->transactionff);
    }
    osip_fifo_free (transaction->transactionff);
  }

  osip_message_free (transaction->orig_request);
  osip_message_free (transaction->last_response);
  osip_message_free (transaction->ack);

  osip_via_free (transaction->topvia);
  osip_from_free (transaction->from);
  osip_to_free (transaction->to);
  osip_call_id_free (transaction->callid);
  osip_cseq_free (transaction->cseq);

  osip_free (transaction);
  return OSIP_SUCCESS;
}

int
osip_transaction_add_event (osip_transaction_t * transaction, osip_event_t * evt)
{
  if (evt == NULL)
    return OSIP_BADPARAMETER;
  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  evt->transactionid = transaction->transactionid;
  osip_fifo_add (transaction->transactionff, evt);
  return OSIP_SUCCESS;
}

//evt是从transaction->transactionff中取出来的
//根据transaction->state(事务的当前状态)和evt->type(新收到消息的类型) 来执行相应的状态机函数
int
osip_transaction_execute (osip_transaction_t * transaction, osip_event_t * evt)
{
  osip_statemachine_t *statemachine;

  /* to kill the process, simply send this type of event. */
  if (EVT_IS_KILL_TRANSACTION (evt)) {
    /* MAJOR CHANGE!
       TRANSACTION MUST NOW BE RELEASED BY END-USER:
       So Any usefull data can be save and re-used */
    /* osip_transaction_free(transaction);
       osip_free(transaction); */
    osip_free (evt);
    return OSIP_SUCCESS;
  }

  OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_INFO4, NULL, "sipevent tr->transactionid: %i\n", transaction->transactionid));
  OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_INFO4, NULL, "sipevent tr->state: %i\n", transaction->state));
  OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_INFO4, NULL, "sipevent evt->type: %i\n", evt->type));
  OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_INFO4, NULL, "sipevent evt->sip: %x\n", evt->sip));

  if (transaction->ctx_type == ICT)
    statemachine = &ict_fsm;
  else if (transaction->ctx_type == IST)
    statemachine = &ist_fsm;
  else if (transaction->ctx_type == NICT)
    statemachine = &nict_fsm;
  else
    statemachine = &nist_fsm;

  if (0 != fsm_callmethod (evt->type, transaction->state, statemachine, evt, transaction)) {
    OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_INFO3, NULL, "USELESS event!\n"));
    /* message is useless. */
    if (EVT_IS_MSG (evt)) {
      if (evt->sip != NULL) {
        osip_message_free (evt->sip);
      }
    }
  }
  else {
    OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_INFO4, NULL, "sipevent evt: method called!\n"));
  }
  osip_free (evt);              /* this is the ONLY place for freeing event!! */
  return 1;
}

int
osip_transaction_get_destination (osip_transaction_t * transaction, char **ip, int *port)
{
  *ip = NULL;
  *port = 0;
  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  if (transaction->ict_context != NULL) {
    *ip = transaction->ict_context->destination;
    *port = transaction->ict_context->port;
    return OSIP_SUCCESS;
  }
  else if (transaction->nict_context != NULL) {
    *ip = transaction->nict_context->destination;
    *port = transaction->nict_context->port;
    return OSIP_SUCCESS;
  }
  return OSIP_UNDEFINED_ERROR;
}

int
osip_transaction_set_srv_record (osip_transaction_t * transaction, osip_srv_record_t * record)
{
  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  memcpy (&transaction->record, record, sizeof (osip_srv_record_t));
  return OSIP_SUCCESS;
}

int
osip_transaction_set_naptr_record (osip_transaction_t * transaction, osip_naptr_t * record)
{
  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  transaction->naptr_record = record;
  return OSIP_SUCCESS;
}

int
osip_transaction_set_your_instance (osip_transaction_t * transaction, void *ptr)
{
  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  transaction->reserved1 = ptr;
  return OSIP_SUCCESS;
}

int
osip_transaction_set_reserved1 (osip_transaction_t * transaction, void *ptr)
{
  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  transaction->reserved1 = ptr;
  return OSIP_SUCCESS;
}

int
osip_transaction_set_reserved2 (osip_transaction_t * transaction, void *ptr)
{
  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  transaction->reserved2 = ptr;
  return OSIP_SUCCESS;
}

int
osip_transaction_set_reserved3 (osip_transaction_t * transaction, void *ptr)
{
  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  transaction->reserved3 = ptr;
  return OSIP_SUCCESS;
}

int
osip_transaction_set_reserved4 (osip_transaction_t * transaction, void *ptr)
{
  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  transaction->reserved4 = ptr;
  return OSIP_SUCCESS;
}

int
osip_transaction_set_reserved5 (osip_transaction_t * transaction, void *ptr)
{
  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  transaction->reserved5 = ptr;
  return OSIP_SUCCESS;
}

int
osip_transaction_set_reserved6 (osip_transaction_t * transaction, void *ptr)
{
  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  transaction->reserved6 = ptr;
  return OSIP_SUCCESS;
}


void *
osip_transaction_get_your_instance (osip_transaction_t * transaction)
{
  if (transaction == NULL)
    return NULL;
  return transaction->reserved1;
}

void *
osip_transaction_get_reserved1 (osip_transaction_t * transaction)
{
  if (transaction == NULL)
    return NULL;
  return transaction->reserved1;
}

void *
osip_transaction_get_reserved2 (osip_transaction_t * transaction)
{
  if (transaction == NULL)
    return NULL;
  return transaction->reserved2;
}

void *
osip_transaction_get_reserved3 (osip_transaction_t * transaction)
{
  if (transaction == NULL)
    return NULL;
  return transaction->reserved3;
}

void *
osip_transaction_get_reserved4 (osip_transaction_t * transaction)
{
  if (transaction == NULL)
    return NULL;
  return transaction->reserved4;
}

void *
osip_transaction_get_reserved5 (osip_transaction_t * transaction)
{
  if (transaction == NULL)
    return NULL;
  return transaction->reserved5;
}

void *
osip_transaction_get_reserved6 (osip_transaction_t * transaction)
{
  if (transaction == NULL)
    return NULL;
  return transaction->reserved6;
}


int
__osip_transaction_set_state (osip_transaction_t * transaction, state_t state)
{
  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  transaction->state = state;
  return OSIP_SUCCESS;
}

int
osip_transaction_set_in_socket (osip_transaction_t * transaction, int sock)
{
  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  transaction->in_socket = sock;
  return OSIP_SUCCESS;
}

int
osip_transaction_set_out_socket (osip_transaction_t * transaction, int sock)
{
  if (transaction == NULL)
    return OSIP_BADPARAMETER;
  transaction->out_socket = sock;
  return OSIP_SUCCESS;
}

int
__osip_transaction_matching_response_osip_to_xict_17_1_3 (osip_transaction_t * tr, osip_message_t * response)
{
  osip_generic_param_t *b_request;
  osip_generic_param_t *b_response;
  osip_via_t *topvia_response;

  /* some checks to avoid crashing on bad requests */
  if (tr == NULL || (tr->ict_context == NULL && tr->nict_context == NULL) ||
      /* only ict and nict can match a response */
      response == NULL || response->cseq == NULL || response->cseq->method == NULL)
    return OSIP_BADPARAMETER;

  topvia_response = osip_list_get (&response->vias, 0);
  if (topvia_response == NULL) {
    OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_ERROR, NULL, "Remote UA is not compliant: missing a Via header!\n"));
    return OSIP_SYNTAXERROR;
  }
  osip_via_param_get_byname (tr->topvia, "branch", &b_request);
  if (b_request == NULL) {
    OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_BUG, NULL, "You created a transaction without any branch! THIS IS NOT ALLOWED\n"));
    return OSIP_SYNTAXERROR;
  }
  osip_via_param_get_byname (topvia_response, "branch", &b_response);
  if (b_response == NULL) {   //如果收到的回复消息的topvia中没有branch字段
#ifdef FWDSUPPORT  //定义了这个宏，就判断from_tag，cseq等。这里我们先不看 2018.10.15
    /* the from tag (unique) */
    if (from_tag_match (tr->from, response->from) != 0)
      return OSIP_UNDEFINED_ERROR;
    /* the Cseq field */
    if (cseq_match (tr->cseq, response->cseq) != 0)
      return OSIP_UNDEFINED_ERROR;
    /* the To field */
    if (response->to->url->username == NULL && tr->from->url->username != NULL)
      return OSIP_UNDEFINED_ERROR;
    if (response->to->url->username != NULL && tr->from->url->username == NULL)
      return OSIP_UNDEFINED_ERROR;
    if (response->to->url->username != NULL && tr->from->url->username != NULL) {
      if (strcmp (response->to->url->host, tr->from->url->host) || strcmp (response->to->url->username, tr->from->url->username))
        return OSIP_UNDEFINED_ERROR;
    }
    else {
      if (strcmp (response->to->url->host, tr->from->url->host))
        return OSIP_UNDEFINED_ERROR;
    }

    /* the Call-ID field */
    if (call_id_match (tr->callid, response->call_id) != 0)
      return OSIP_UNDEFINED_ERROR;
    return OSIP_SUCCESS;
#else
    OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_BUG, NULL, "Remote UA is not compliant: missing a branch parameter in  Via header!\n"));
    return OSIP_SYNTAXERROR;   //我们认为，收到的回复消息topvia不存在branch，则事务不匹配
#endif
  }

  if ((b_request->gvalue == NULL)
      || (b_response->gvalue == NULL)) {  //我们之前发送的消息，或者我们收到的回复消息中的topvia的branch值为null，则不匹配
    OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_BUG, NULL, "Remote UA is not compliant: missing a branch parameter in  Via header!\n"));
    return OSIP_SYNTAXERROR;
  }

  /*
     A response matches a client transaction under two
     conditions:

     1.   If the response has the same value of the branch parameter
     in the top Via header field as the branch parameter in the
     top Via header field of the request that created the
     transaction.
   */
  if (0 != strcmp (b_request->gvalue, b_response->gvalue))
    return OSIP_UNDEFINED_ERROR;
  /*  
     2.   If the method parameter in the CSeq header field matches
     the method of the request that created the transaction. The
     method is needed since a CANCEL request constitutes a
     different transaction, but shares the same value of the
     branch parameter.
     AMD NOTE: cseq->method is ALWAYS the same than the METHOD of the request.
   */
  if (0 == strcmp (response->cseq->method, tr->cseq->method))   /* general case */
    return OSIP_SUCCESS;
  return OSIP_UNDEFINED_ERROR;
}

int
__osip_transaction_matching_request_osip_to_xist_17_2_3 (osip_transaction_t * tr, osip_message_t * request)
{
  osip_generic_param_t *b_origrequest;
  osip_generic_param_t *b_request;
  osip_via_t *topvia_request;
  size_t length_br;
  size_t length_br2;

  /* some checks to avoid crashing on bad requests */
  if (tr == NULL || (tr->ist_context == NULL && tr->nist_context == NULL) ||
      /* only ist and nist can match a request */
      request == NULL || request->cseq == NULL || request->cseq->method == NULL)
    return OSIP_BADPARAMETER;

  topvia_request = osip_list_get (&request->vias, 0);  //get topvia
  if (topvia_request == NULL) {
    OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_ERROR, NULL, "Remote UA is not compliant: missing a Via header!\n"));
    return OSIP_SYNTAXERROR;
  }
  osip_via_param_get_byname (topvia_request, "branch", &b_request);  //从收到的sip消息的topvia中得到branch
  osip_via_param_get_byname (tr->topvia, "branch", &b_origrequest);  //从已存在的transaction的topvia中得到branch

  if ((b_origrequest == NULL && b_request != NULL) || (b_origrequest != NULL && b_request == NULL))
    return OSIP_SYNTAXERROR;    /* one request is compliant, the other one is not... */

  /* Section 17.2.3 Matching Requests to Server Transactions:
     "The branch parameter in the topmost Via header field of the request
     is examined. If it is present and begins with the magic cookie
     "z9hG4bK", the request was generated by a client transaction
     compliant to this specification."
   */

  if (b_origrequest != NULL && b_request != NULL)
    /* case where both request contains a branch */
  {
    if (!b_origrequest->gvalue)
      return OSIP_UNDEFINED_ERROR;
    if (!b_request->gvalue)
      return OSIP_UNDEFINED_ERROR;

    length_br = strlen (b_origrequest->gvalue);
    length_br2 = strlen (b_request->gvalue);
    if (length_br != length_br2)
      return OSIP_UNDEFINED_ERROR;

    /* can't be the same */
    if (0 == strncmp (b_origrequest->gvalue, "z9hG4bK", 7)
        && 0 == strncmp (b_request->gvalue, "z9hG4bK", 7)) {  //compliant UA 符合标准的UA
      /* both request comes from a compliant UA */
      /* The request matches a transaction if the branch parameter
         in the request is equal to the one in the top Via header
         field of the request that created the transaction, the
         sent-by value in the top Via of the request is equal to
         the one in the request that created the transaction, and in
         the case of a CANCEL request, the method of the request
         that created the transaction was also CANCEL.
       */
      if (0 != strcmp (b_origrequest->gvalue, b_request->gvalue))
        return OSIP_UNDEFINED_ERROR;    /* branch param does not match */
      {           //如果是符合标准的sip消息，先匹配via branch，再匹配via ip和via port，都一直，则该transaction存在
        /* check the sent-by values */
        char *b_port = via_get_port (topvia_request);
        char *b_origport = via_get_port (tr->topvia);
        char *b_host = via_get_host (topvia_request);
        char *b_orighost = via_get_host (tr->topvia);

        if ((b_host == NULL || b_orighost == NULL))
          return OSIP_UNDEFINED_ERROR;
        if (0 != strcmp (b_orighost, b_host))
          return OSIP_UNDEFINED_ERROR;

        if (b_port != NULL && b_origport == NULL && 0 != strcmp (b_port, "5060"))
          return OSIP_UNDEFINED_ERROR;
        else if (b_origport != NULL && b_port == NULL && 0 != strcmp (b_origport, "5060"))
          return OSIP_UNDEFINED_ERROR;
        else if (b_origport != NULL && b_port != NULL && 0 != strcmp (b_origport, b_port))
          return OSIP_UNDEFINED_ERROR;
      }
#ifdef AC_BUG
      /* audiocodes bug (MP108-fxs-SIP-4-0-282-380) */
      if (0 != osip_from_tag_match (tr->from, request->from))  //不清楚这个条件宏的含义 2018.10.12
        return OSIP_UNDEFINED_ERROR;
#endif
      if (                      /* MSG_IS_CANCEL(request)&& <<-- BUG from the spec?
                                   I always check the CSeq */
           (!(0 == strcmp (tr->cseq->method, "INVITE") && 0 == strcmp (request->cseq->method, "ACK")))
           && 0 != strcmp (tr->cseq->method, request->cseq->method))  //tr和request类型不相等的前提下，tr不是invite、request不是ack?
        return OSIP_UNDEFINED_ERROR;
      return OSIP_SUCCESS;
    }
  }

  /* Back to the old backward compatibilty mechanism for matching requests */
  if (0 != osip_call_id_match (tr->callid, request->call_id))
    return OSIP_UNDEFINED_ERROR;  //don't want to see this in 2018.10.12 22:15，maybe previous code is enough
  if (MSG_IS_ACK (request)) {
    osip_generic_param_t *tag_from1;
    osip_generic_param_t *tag_from2;

    osip_from_param_get_byname (tr->to, "tag", &tag_from1);
    osip_from_param_get_byname (request->to, "tag", &tag_from2);
    if (tag_from1 == NULL && tag_from2 != NULL) {       /* do not check it as it can be a new tag when the final
                                                           answer has a tag while an INVITE doesn't have one */
    }
    else if (tag_from1 != NULL && tag_from2 == NULL) {
      return OSIP_UNDEFINED_ERROR;
    }
    else {
      if (0 != osip_to_tag_match (tr->to, request->to))
        return OSIP_UNDEFINED_ERROR;
    }
  }
  else {
    if (tr->orig_request == NULL || tr->orig_request->to == NULL)
      return OSIP_UNDEFINED_ERROR;
    if (0 != osip_to_tag_match (tr->orig_request->to, request->to))
      return OSIP_UNDEFINED_ERROR;
  }
  if (0 != osip_from_tag_match (tr->from, request->from))
    return OSIP_UNDEFINED_ERROR;
  if (0 != osip_cseq_match (tr->cseq, request->cseq))
    return OSIP_UNDEFINED_ERROR;
  if (0 != osip_via_match (tr->topvia, topvia_request))
    return OSIP_UNDEFINED_ERROR;
  return OSIP_SUCCESS;
}

osip_event_t *
__osip_transaction_need_timer_x_event (void *xixt, struct timeval * timer, int cond_state, int transactionid, int TIMER_VAL)
{
  struct timeval now;

  osip_gettimeofday (&now, NULL);

  if (xixt == NULL)
    return NULL;
  if (cond_state) {
    if (timer->tv_sec == -1)
      return NULL;
    if (osip_timercmp (&now, timer, >))
      return __osip_event_new (TIMER_VAL, transactionid);
  }
  return NULL;
}

//发送回复消息
//发送的目的host/port填充方式如下:
//1.topvia maddr不空，host = maddr->gvalue，否则host = received->gvalue，
//如果topvia received也为空，host = topvia->host
//2.rport不空，port = rport->gvalue，否则port = topvia->port
int
__osip_transaction_snd_xxx (osip_transaction_t * ist, osip_message_t * msg)
{
  osip_t *osip = (osip_t *) ist->config;
  osip_via_t *via;
  char *host;
  int port;
  osip_generic_param_t *maddr;
  osip_generic_param_t *received;
  osip_generic_param_t *rport;

  via = (osip_via_t *) osip_list_get (&msg->vias, 0);
  if (!via)
    return OSIP_SYNTAXERROR;

  osip_via_param_get_byname (via, "maddr", &maddr);
  osip_via_param_get_byname (via, "received", &received);
  osip_via_param_get_byname (via, "rport", &rport);
  /* 1: user should not use the provided information
     (host and port) if they are using a reliable
     transport. Instead, they should use the already
     open socket attached to this transaction. */
  /* 2: check maddr and multicast usage */
  if (maddr != NULL)
    host = maddr->gvalue;
  /* we should check if this is a multicast address and use
     set the "ttl" in this case. (this must be done in the
     UDP message (not at the SIP layer) */
  else if (received != NULL)
    host = received->gvalue;
  else
    host = via->host;

  if (rport == NULL || rport->gvalue == NULL) {
    if (via->port != NULL)
      port = osip_atoi (via->port);
    else
      port = 5060;
  }
  else
    port = osip_atoi (rport->gvalue);

  return osip->cb_send_message (ist, msg, host, port, ist->out_socket);

}
