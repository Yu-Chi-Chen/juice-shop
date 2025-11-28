/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

export function retrieveBasket () {
  return (req: Request, res: Response, next: NextFunction) => {
    const id = req.params.id;

    // Step 1: retrieve information about the currently logged-in user
    const currentUser = security.authenticatedUsers.from(req);

    // Step 2: verify whether the user is logged in
    if (!currentUser || !currentUser.bid) {
      return res.status(401).json({
        status: 'error',
        message: 'Authentication required',
      });
    }

    BasketModel.findOne({
      where: { id },
      include: [{ model: ProductModel, paranoid: false, as: 'Products' }],
    })
      .then((basket: BasketModel | null) => {
        // Step 3: check whether the basket is exist
        if (!basket) {
          return res.status(404).json({
            status: 'error',
            message: 'Basket not found',
          });
        }

        // Step 4: check authorization
        // compare the basket owner ID with the current user's basket ID
        if (basket.id !== currentUser.bid) {
          // Log unauthorized access attempts for security monitoring
          console.warn({
            event: 'UNAUTHORIZED_BASKET_ACCESS_ATTEMPT',
            userId: currentUser.id,
            userBasketId: currentUser.bid,
            attemptedBasketId: id,
            timestamp: new Date().toISOString(),
            ip: req.ip,
          });

          return res.status(403).json({
            status: 'error',
            message: 'Access denied: You can only access your own basket',
          });
        }

        // Step 5: if all checks pass, return the data
        if (basket.Products && basket.Products.length > 0) {
          for (let i = 0; i < basket.Products.length; i++) {
            basket.Products[i].name = req.__(basket.Products[i].name);
          }
        }
        res.json(utils.queryResultToJson(basket));
      })
      .catch((error: Error) => {
        next(error);
      });
  };
}
