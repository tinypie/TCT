#include "plugin.h"

/*
 * Global variables
 */
u_int32_t class_hits = 0;
u_int32_t class_miss = 0;
u_int32_t class_forced = 0;


/*
 * Decide if the classification process
 * can start for the session specified.
 */
Bool is_session_classifiable(void *sess)
{
	int i, duration = 0;

	switch (tct_opts.session_type) {
	case SESSION_TYPE_FLOW: {
		struct flow_entry *s = sess;

		/* Compute session duration */
		duration = elapsed(s->ete->last_time,  s->ete->first_time);

		break;
	}
	case SESSION_TYPE_BFLOW: {
		struct bflow_entry *s = sess;
		//struct connection *pct = s->ete;

		/* Compute session duration */
		//duration = s->ete->last_time - s->ete->first_time;
		duration = elapsed(s->ete->last_time,  s->ete->first_time);

		/* Test if the session has at least one packet carrying payload */ 
		/* IMPORTANT NOTE: Currently TIE forces UNKNOWN on all biflows which do not contain payload */
//		if ( pct->c2s.pure_ack_pkts < 1  &&
//			pct->s2c.pure_ack_pkts < 1)
		    
		if (s->ete->c2s.pure_ack_pkts < 1 && s->ete->s2c.pure_ack_pkts < 1)
			return false;
		break;
	}
	case SESSION_TYPE_PKT: {
		//struct host *s = sess;
		break;
	}
	}

	/*
	 * Take decision depending on is_session_classifiable() from each plugin.
	 * Rationale: wait for all classifiers to be able to perform classification attempt,
	 * or wait CLASS_TIMEOUT seconds to attempt classification with only those that are available.
	 */
	if (duration > SESSION_TIMEOUT) {
		/* Classification Timeout exceeded => Classify if there is at least one classifier willing */
		for (i = 0; i < tct_plg.num_classifiers; i++)
			if (TEST_BIT(*(tct_plg.classifiers[i].flags), CLASS_ENABLE, 1) && tct_plg.classifiers[i].is_session_classifiable(sess))
				return true;
		return false;
	} else {
		/* Classify if ALL classifiers are willing to classify */
		for (i = 0; i < tct_plg.num_classifiers; i++)
			if (TEST_BIT(*(tct_plg.classifiers[i].flags), CLASS_ENABLE, 1) && !tct_plg.classifiers[i].is_session_classifiable(sess))
				return false;
		return true;
	}
}
/*
 * Let each classifier take its decision in turn and compute the final response
 * there are two strategy, one is using a priority based approach
 * the other is using thread 
 */
int classify(void *sess)
{
	int i;
	struct tct_result *result;

	switch (tct_opts.session_type) {
#if 0
	case SESSION_TYPE_FLOW: {
		struct flow_entry *s = sess;

		//printf("FLAGS before: %08X\t", s->ete->flags);
		SET_BIT(s->ete->flags, SESS_RECLASSIFY, 0);
		//s->ete->app.confidence = 0;
		/*
		 * For every classifier
		 */
		for (i = 0; i < tct_plg.num_classifiers; i++) {
			/* Skip current classifier if disabled */
			if (TEST_BIT(*(tct_plg.classifiers[i].flags), CLASS_ENABLE, 0))
				continue;

			/* Skip current classifier if cannot attempt classification */
			if (! (tct_plg.classifiers[i].is_session_classifiable(s)))
				continue;

			/* Perform classification */
			result = tct_plg.classifiers[i].classify_session(s);

			/* If current classifier wants to retry classification process set SESS_RECLASSIFY */
			if (TEST_BIT(result->flags, CLASS_OUT_REDO, 1))
				SET_BIT(s->ete->flags, SESS_RECLASSIFY, 1);

			s->ete->type[i].group_id = result->group_id;
			s->ete->type[i].sub_id = result->sub_id;

			#if 0
			/*
			 * If current classifier gives a result != UNKNOWN then apply the following priority scheme:
			 * - Classifiers priority is given by the order in which they are called
			 * - The output class is determined by the first classifier that recognizes the session
			 * - Agreement or disagreement of subsequent classifiers only affects output confidence.
			 */
			if (TEST_BIT(result->flags, CLASS_OUT_ERR, 0) && (result->group_id != 0)) {
				if (s->ete->type[i].group_id == 0) {	/* the previous classifiers did not recognize the session */
					s->ete->type[i].group_id = result->group_id;
					s->ete->type[i].sub_id = result->sub_id;
					s->ete->type[i].confidence += result->confidence / tct_plg.enabled_classifiers;
				} else if (s->ete->type[i].group_id == result->group_id) { /* current classifier agrees with previous classifiers */
					/* Increase confidence */
					s->ete->type[i].confidence += result->confidence / tct_plg.enabled_classifiers;
				} else {		/* current classifier disagrees with previous classifiers */
					/* Decrease confidence */
					s->ete->type[i].confidence /= 2;
				}
			}
			#endif 

			free(result);
		}

		/*
		 * At the end of this code block the session will be flagged with one of the following:
		 * - SESS_RECLASSIFY
		 * - SESS_DONT_CLASSIFY
		 * - SESS_CLASSIFIED
		 */
		if (TEST_BIT(s->ete->flags, SESS_RECLASSIFY, 1)) {
			/*
			 * If it's realtime mode and we received at least two pkts with payload:
			 * - force to not attempt any reclassifications 
			 * - set the session either in DON'T CLASSIFY -- if it was an unknown 
			 * - or to CLASSIFIED if otherwise
			 */
			if (tct_opts.work_mode == MODE_REALTIME && s->pl_pkts > 2) {
				SET_BIT(s->ete->flags, s->ete->type[i].confidence == 0 ? SESS_DONT_CLASSIFY : SESS_CLASSIFIED, 1);
				SET_BIT(s->ete->flags, SESS_RECLASSIFY, 0);
				if (s->ete->type[i].group_id == 0) {
					class_miss++;
				} else {
					class_hits++;
				}
				class_forced++;
			}
			/* Otherwise implicitly let the SESS_RECLASSIFY flag set */
		} else if (s->ete->type[i].group_id == 0) {
			SET_BIT(s->ete->flags, SESS_DONT_CLASSIFY, 1);
			class_miss++;
		} else {
			SET_BIT(s->ete->flags, SESS_CLASSIFIED, 1);
			class_hits++;
		}
		printf("FLAGS after: %08X\n", s->ete->flags);
		break;
	}
#endif
	case SESSION_TYPE_BFLOW: {
		struct bflow_entry *s = sess;

		SET_BIT(s->ete->flags, SESS_RECLASSIFY, 0);

		/*
		 * For every classifier
		 */
		for (i = 0; i < tct_plg.num_classifiers; i++) {
			/* Skip current classifier if disabled */
			if (TEST_BIT(*(tct_plg.classifiers[i].flags), CLASS_ENABLE, 0))
				continue;

			/* Skip current classifier if cannot attempt classification */
			if (! tct_plg.classifiers[i].is_session_classifiable(s))
				continue;

			/*
			 * Perform classification
			 * here can using thread 
			 */
			result = tct_plg.classifiers[i].classify_session(s);

			/* If current classifier wants to retry classification process set SESS_RECLASSIFY */
			if (TEST_BIT(result->flags, CLASS_OUT_REDO, 1))
				SET_BIT(s->ete->flags, SESS_RECLASSIFY, 1);

			if (TEST_BIT(result->flags, CLASS_OUT_ERR, 0) && (result->app_id != 0)) {
				s->ete->type[i].app_id = result->app_id;
				s->ete->type[i].sub_id = result->sub_id;
				s->ete->type[i].group_id = tct_app[result->app_id].group_id;
				s->ete->type[i].confidence = 100;
				s->ete->type[i].flags = result->flags;
				strcpy(s->ete->type[i].name, tct_plg.classifiers[i].name);

				SET_BIT(s->ete->flags, SESS_CLASSIFIED, 1);
				s->ete->confidence++;
			}
#if 0
			/*
			 * If current classifier gives a result != UNKNOWN then apply the following priority scheme:
			 * - Classifiers priority is given by the order in which they are called
			 * - The output class is determined by the first classifier that recognizes the session
			 * - Agreement or disagreement of subsequent classifiers only affects output confidence.
			 */
			if (TEST_BIT(result->flags, CLASS_OUT_ERR, 0) && (result->group_id != 0)) {
				/* 
				 * the previous classifiers did not recognize the session or 
				 * result was set by the current classifier in a previous classification round (SESS_RECLASSIFY was set) 
				 * XXX: biflows only 
				 */
				if ( (s->ete->type[i].group_id == 0) || (s->id_class == i ) ) {
					s->id_class = i;
					s->ete->type[i].group_id = result->group_id;
					s->ete->type[i].sub_id = result->sub_id;
					s->ete->type[i].confidence += result->confidence / tct_plg.enabled_classifiers;
				} else if (s->ete->type[i].group_id == result->group_id) {	/* current classifier agrees with previous classifiers */
					/* Increase confidence */
					s->ete->type[i].confidence += result->confidence / tct_plg.enabled_classifiers;
				} else {				/* current classifier disagrees with previous classifiers */
					/* Decrease confidence */
					s->ete->type[i].confidence /= 2;
				}
			}
#endif

			free(result);
		}

		/*
		 * At the end of this code block, the session will be flagged with one of the following:
		 * - SESS_RECLASSIFY
		 * - SESS_DONT_CLASSIFY
		 * - SESS_CLASSIFIED
		 */
		if (TEST_BIT(s->ete->flags, SESS_RECLASSIFY, 1)) {		/* session will be reclassified */
			/*
			 * If it's realtime mode and we received at least two pkts with payload:
			 * - force to not attempt any reclassifications 
			 * - set the session either in DON'T CLASSIFY -- if it was an unknown 
			 * - or to CLASSIFIED if otherwise
			 */
			if (tct_opts.work_mode == MODE_REALTIME && 
				s->ete->c2s.data_pkts  + s->ete->s2c.data_pkts > 2) {
				SET_BIT(s->ete->flags, (s->ete->confidence == 0 ? SESS_DONT_CLASSIFY : SESS_CLASSIFIED), 1);
				SET_BIT(s->ete->flags, SESS_RECLASSIFY, 0);
				if (s->ete->type[i].group_id == 0) {
					class_miss++;
				} else {





	// here can give the final result, as voted

					class_hits++;
				}
				class_forced++;
			}
		} else { 		/* Otherwise implicitly let the SESS_RECLASSIFY flag set */
			if (s->ete->confidence == 0) {				/* session won't be reclassified and is unknown */
				SET_BIT(s->ete->flags, SESS_DONT_CLASSIFY, 1);
				class_miss++;
			} else {						/* session won't be reclassified and is known */
				SET_BIT(s->ete->flags, SESS_CLASSIFIED, 1);






	// here can give the final result, as voted

				class_hits++;
			}	
		}

		} 
	} 
	return 0;
}
