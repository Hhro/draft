import numpy as np

import asm2vec.asm
import asm2vec.parse
import asm2vec.model


import glob
import sys

from tqdm import tqdm
from typing import List, Dict
from pathlib import Path


def cosine_similarity(v1, v2):
    return np.dot(v1, v2) / (np.linalg.norm(v1) * np.linalg.norm(v2))


def train(trainees: List[Path], targets: List[Path], train_xref, target_xref, tifs):
    training_funcs = []
    estimating_funcs = []

    print(f"Prepare Target Repository")
    for target in tqdm(targets):
        try:
            fncs = []
            for tif in tifs:
                fncs += (target_xref[str(target)][tif])
            estimating_funcs += (asm2vec.parse.parse(str(target),
                                                     func_names=fncs))
        except:
            continue
    print('# of estimating functions:', len(estimating_funcs))

    print(f"Prepare Function Repository")
    trainees = trainees[:10]

    for corp in tqdm(trainees):
        try:
            fncs = []
            for tif in tifs:
                xref_fncs = train_xref[str(corp)][tif]

                while "" in xref_fncs:
                    xref_fncs.remove("")

                fncs += train_xref[str(corp)][tif]

            training_funcs += (asm2vec.parse.parse(str(corp),
                                                   func_names=fncs))
        except:
            continue

    print('# of training functions:', len(training_funcs))

    print("[i]Train")
    model = asm2vec.model.Asm2Vec(d=200)
    training_repo = model.make_function_repo(training_funcs)
    model.train(training_repo)
    print('Training complete.')

    for tf in training_repo.funcs():
        print('Norm of trained function "{}" = {}'.format(
            tf.sequential().name(), np.linalg.norm(tf.v)))

    estimating_funcs_vec = list(
        map(lambda f: model.to_vec(f), estimating_funcs))
    print('Estimating complete.')

    for (ef, efv) in zip(estimating_funcs, estimating_funcs_vec):
        print('Norm of trained function "{}" = {}'.format(
            ef.name(), np.linalg.norm(efv)))

    for tf in training_repo.funcs():
        for (ef, efv) in zip(estimating_funcs, estimating_funcs_vec):
            sim = cosine_similarity(tf.v, efv)
            print('sim("{}", "{}") = {}'.format(
                tf.sequential().name(), ef.name(), sim))
