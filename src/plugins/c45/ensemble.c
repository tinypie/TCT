#include "class_c45.h"

float *en_weight;
int *perm;
double *p;
double *ada_alp;
int *hash;

union attribute_value **en_item;
struct tree_record **ada_tree;
struct tree_record **bag_tree;

/* Sort a[] into descending order by "heapsort";
 * sort ib[] alongside;
 * if initially, ib[] = 1...n, it will contain the permutation finally
 */
static void revsort(double *a, int *ib, int n)
{
	int l, j, ir, i;
	double ra;
	int ii;

	if (n <= 1)
		return;

	a--;
	ib--;

	l = (n >> 1) + 1;
	ir = n;

	for (;;) {
		if (l > 1) {
			l = l - 1;
			ra = a[l];
			ii = ib[l];
		} else {
			ra = a[ir];
			ii = ib[ir];
			a[ir] = a[1];
			ib[ir] = ib[1];
			if (--ir == 1) {
				a[1] = ra;
				ib[1] = ii;
				return;
			}
		}
		i = l;
		j = l << 1;
		while (j <= ir) {
			if (j < ir && a[j] > a[j + 1])
				++j;
			if (ra > a[j]) {
				a[i] = a[j];
				ib[i] = ib[j];
				j += (i = j);
			} else
				j = ir + 1;
		}
		a[i] = ra;
		ib[i] = ii;
	}
}

static double unif_rand()
{
	return rand() / (double) RAND_MAX;
}

int initial_ensemble()
{
	int i;
	en_weight = (float *) malloc(max_items * sizeof (float));
	en_item = (union attribute_value **) malloc(max_items * sizeof (union attribute_value *));
	hash = (int *)malloc(max_class * sizeof(int));

	ada_tree = (struct tree_record **) malloc(NUM_ENSEMBLE * sizeof (struct tree_record *));
	bag_tree = (struct tree_record **) malloc(NUM_ENSEMBLE * sizeof (struct tree_record *));
	perm = (int *) malloc(max_items * sizeof(int));
	p = (double *) malloc(max_items * sizeof(double));
	ada_alp = (double *) malloc(NUM_ENSEMBLE * sizeof(double));


	/* C4.5 中数据集是存放在item[]数组中的，为了避免分类器程序的大量修改
	 * 抽样后的数据放在item[]中，原始数据保存在en_item数组中
	 */
	for (i = 0; i < max_items; i++) {
		en_weight[i] = 1.0 / max_items;
		en_item[i] = item[i];
	}

	srand(time(NULL));

	return 0;
}

/* unequal probabilities sampleing: with replacement */
int ada_sample(int max_items)
{
	int i, j, s;
	double ru;

	/* record element identities */
	for (i = 0; i < max_items; i++) {
		perm[i] = i;
		p[i] = en_weight[i];
	}
	
	/* sort the probabilities into descending order */
	revsort(p, perm, max_items);

	/* compute cumulative probabilities */
	for (i = 1; i < max_items; i++)
		p[i] += p[i - 1];

	/* compute the sample */
	for (i = 0; i < max_items; i++) {
		ru = unif_rand();
		for (j = 0; j < max_items-1; j++) {
			if (ru <= p[j])
				break;
		}
		s = perm[j];
		item[i] = en_item[s];
	}

	return 0;
}

double ada_error(struct tree_record *tree)
{
	int i;
	double error = 0;

	for (i = 0; i < max_items; i++) {
		if (category(en_item[i], tree) != CLASS(en_item[i])) {
			error += en_weight[i];
		}
	}
//	error /= max_items;
	return error;
}

int adjust_weight(struct tree_record *tree, double error)
{
	int i, real_class;
	double sum = 0.0, a;
	
	a = (1 - error) / error;

	for (i = 0; i < max_items; i++) {
		real_class = CLASS(en_item[i]);
		if (category(en_item[i], tree) != real_class) {	
			en_weight[i] = en_weight[i] * a * exp(0.5);
		} else {
			en_weight[i] = en_weight[i] * a * exp(-0.5);
		}
		
		sum += en_weight[i];
	}

	/* normalized weight array */
	for (i = 0; i < max_items; i++) {
		en_weight[i] /= sum;
	}

	return 0;
}

int en_evaluation(struct tree_record **tree, int boost)
{
	int i, j;
	int real_class, for_class, tmp_class, max_count;
	float accu, errors = 0;
	
	initial_measure(1);


	for (i = 0; i < max_items; i++) {
		/* reset the hash table */
		for (j = 0; j < max_class; j++) {
			hash[j] = 0;
		}

		/* for each classifier */
		max_count = 0;
		for_class = 0;
		for (j = 0; j < NUM_ENSEMBLE; j++) {
			tmp_class = category(en_item[i], tree[j]);
			if (boost == 1)
				hash[tmp_class] += ada_alp[j];
			else 	
				hash[tmp_class]++;

			if (max_count < hash[tmp_class]) {	
				max_count = hash[tmp_class];
				for_class = tmp_class;
			}
		}

		real_class = CLASS(en_item[i]);

		if (real_class != for_class) {
			errors++;	
			ms[for_class].fp++;
			ms[real_class].fn++;
		} else {
			ms[real_class].tp++;
			ms[real_class].bytes += (CVAL(en_item[i] ,7) + CVAL(en_item[i] ,58));
		}
	}
	print_measure();

	accu = 100 * (1-errors/max_items);

	printf("\ttotal precision:%.3f%%\n", accu);

	return 0;
}
/* 
 * adaBoost algorithm
 * NUM_ENSEMBLE is the boosting times
 */
int ada_boost()
{
	int i, j, size;
	char str[32];
	double error;

	size = SCALE * max_items;

	for (i = 0; i < NUM_ENSEMBLE; i++) {
		printf("\nin %d boosting\n", i+1);
		ada_sample(max_items);

		initialise_weights();
		all_known = 1;
	//	ada_tree[i] = form_tree(0, max_items - 1);
		ada_tree[i] = form_tree(0, size);
		prune(ada_tree[i]);
		sprintf(str, ".ada%d", i);
		save_tree(ada_tree[i], str);

		error = ada_error(ada_tree[i]);

		ada_alp[i] = 0.5 * log((1-error)/error);

		if (error > 0.5) {
			for (j = 0; j <max_items; j++) {
				en_weight[j] = 1 / max_items;
			}

			i--;
			continue;
		}

		adjust_weight(ada_tree[i], error);
	}

	en_evaluation(ada_tree, 1);

	return 0;
}

int bag_sample()
{
	int i, j;

	for (i = 0; i < max_items; i++) {
		item[i] = NULL;

		for (j = 0; j < max_items; j++) {
			if (rand() % (max_items - j) <= 1) {
				item[i] = en_item[j];
				break;
			}
#if 0
	if (rand() % (j+1) < 1) {
		item[i] = en_item[j];
	}

#endif
		}
	}

	return 0;
}

int bagging()
{
	int i;
	char str[32];
	int size = SCALE * max_items;

	initialise_weights();

	for (i = 0; i < NUM_ENSEMBLE; i++) {
		printf("\nin %d baging\n", i+1);
		bag_sample();

		all_known = 1;
		bag_tree[i] = form_tree(0, size);
		//bag_tree[i] = form_tree(0, max_items - 1);
		prune(bag_tree[i]);
		sprintf(str, ".bag%d", i+1);
		save_tree(bag_tree[i], str);
	}

	en_evaluation(bag_tree, 0);

	return 0;
}


int free_ensemble()
{
	int i;

	if (en_weight != NULL) 
		free(en_weight);
	if (en_item != NULL) {
		for (i = 0; i < max_items; i++) {
			item[i] = en_item[i];
		}

		free(en_item);
	}
	if (hash != NULL) 
		free(hash);
	if (perm != NULL)
		free(perm);
	if (p != NULL)

	for (i = 0; i < NUM_ENSEMBLE; i++) {
		if (ada_tree[i] != NULL)
			release_tree(ada_tree[i]);
		if (bag_tree[i] != NULL)
			release_tree(bag_tree[i]);
	}
	free(ada_tree);
	free(bag_tree);

	if (ada_alp != NULL) 
		free(ada_alp);

	return 0;
}
